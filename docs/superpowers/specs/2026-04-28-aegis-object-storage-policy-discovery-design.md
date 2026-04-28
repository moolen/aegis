# Aegis Object Storage Policy Discovery Design

**Date:** 2026-04-28
**Status:** Approved for implementation

## Goal

Add additive remote policy discovery so Aegis can load tenant-defined proxy
policies from provider-native object storage while keeping file-defined
`policies:` as a first-class source.

The design must:

- discover policy documents recursively under a configured bucket/container
  prefix
- support AWS S3, Google Cloud Storage, and Azure Blob Storage
- use the ambient credentials chain of the cloud where Aegis runs by default
- parse Kubernetes-style policy resources, including multi-document YAML files
- reconcile the in-memory discovered-policy state against the latest remote
  snapshot so deletions are applied correctly
- update remote policy state in the background without restarting listeners

## Scope

### In scope

- extend config with remote policy discovery entries under `discovery`
- add provider-native object-store clients for AWS, GCP, and Azure
- poll configured object-store prefixes in the background
- decode remote YAML objects into typed policy resources
- merge file policies and discovered policies into one runtime policy engine
- preserve last-good discovered state on remote poll failures
- support clean removal of remote policies when objects or documents disappear
- add tests, metrics, logs, docs, and example config for the new behavior

### Out of scope

- replacing file-defined `policies:`
- arbitrary cross-cloud credential bootstrapping in this slice
- non-object-store policy sources such as Git or HTTP
- partial-object patching or event-driven watches
- policy-name override precedence rules

## Configuration Model

Add a new discovery registry for remote policy sources:

```yaml
discovery:
  policies:
    - name: prod-aws
      provider: aws
      bucket: aegis-policies
      prefix: tenants/
      pollInterval: 30s
      auth:
        mode: default

    - name: prod-gcp
      provider: gcp
      bucket: aegis-policies
      prefix: tenants/
      pollInterval: 30s
      auth:
        mode: default

    - name: prod-azure
      provider: azure
      bucket: aegis-policies
      prefix: tenants/
      pollInterval: 30s
      auth:
        mode: default
```

### Field semantics

- `name`: stable source identifier used in logs, metrics, and internal state
- `provider`: selects the provider-native backend implementation
  - `aws` => S3
  - `gcp` => GCS
  - `azure` => Blob Storage
- `bucket`: logical object container name across providers
  - for Azure this maps to the blob container name
- `prefix`: optional recursive discovery root within the bucket/container
- `pollInterval`: how often the source is fully re-listed and reconciled
- `auth.mode`: defaults to `default` and means:
  - AWS SDK default credential chain
  - Google application default credentials
  - Azure default credential chain

The config is intentionally provider-neutral at the discovery-entry level so a
later slice can add explicit cross-cloud auth without redesigning the source
model.

### Validation

Validation must be strict:

- `discovery.policies[*].name` is required and unique within policy discovery
  entries
- `provider` must be `aws`, `gcp`, or `azure`
- `bucket` must be non-empty
- `pollInterval` must be greater than zero
- `auth.mode` must currently be `default`

The existing file-defined `policies:` validation remains unchanged and still
applies after remote policies are normalized and merged.

## Remote Resource Shape

Each discovered YAML document is a Kubernetes-style resource:

```yaml
apiVersion: aegis.io/v1alpha1
kind: ProxyPolicy
metadata:
  name: frontend-egress
spec:
  enforcement: enforce
  bypass: false
  subjects:
    kubernetes:
      discoveryNames: ["cluster-a"]
      namespaces: ["frontend"]
      matchLabels:
        app: frontend
  egress:
    - fqdn: api.stripe.com
      ports: [443]
      tls:
        mode: passthrough
```

### Document rules

- one object may contain one or more YAML documents separated by `---`
- each document must decode as `apiVersion: aegis.io/v1alpha1`,
  `kind: ProxyPolicy`
- each resource must provide `metadata.name`
- the resource `spec` maps directly into the existing `config.PolicyConfig`
  shape
- documents that are empty YAML separators may be ignored
- non-empty documents that are not valid `ProxyPolicy` resources cause the
  candidate snapshot for that source to fail

Rejecting invalid documents instead of skipping them keeps remote policy state
legible and gives tenants a clear failure mode.

## Runtime Architecture

### High-level model

Each configured `discovery.policies[]` entry becomes a background poller owned
by the active runtime generation.

The runtime generation already owns reloadable components in
`cmd/aegis/reload.go`; the remote policy pollers should follow the same
lifecycle:

- start when the generation becomes active
- stop when that generation is replaced or shut down
- feed complete discovered-policy snapshots back into the runtime manager

### Provider interface

Add a provider-neutral object discovery layer with provider-specific clients
behind it. At minimum, the client abstraction should support:

- recursive listing under a prefix
- object metadata including stable object key and revision marker if available
- object content reads

The first implementation set is:

- AWS S3 client
- GCS client
- Azure Blob client

This keeps the code organized around a stable discovery contract while still
using native SDK behavior for auth and listing in each cloud.

## Polling And Reconciliation

### Poll algorithm

For each source and each poll cycle:

1. list all objects under the configured prefix recursively
2. fetch candidate YAML objects
3. split each object into YAML documents
4. decode and validate each non-empty document as `ProxyPolicy`
5. normalize each resource into `config.PolicyConfig`
6. build a complete snapshot for that source
7. atomically replace the previous snapshot for that source if the new
   snapshot is valid

The important design choice is full-snapshot reconciliation rather than
incremental patching. A full snapshot makes deletions unambiguous and keeps the
diff logic simple and correct.

### Identity And Diff Keys

Each discovered policy instance is tracked by:

- policy discovery source name
- object URI
- document identity within the object

Recommended internal key:

- `(sourceName, objectURI, metadata.name)`

If resource namespaces are added later, the document identity can widen to
`namespace/name` without changing the rest of the model.

This keying gives the right deletion behavior:

- deleting an object removes every policy contributed by that object
- removing one document from a multi-document object removes only that policy
- renaming a policy is treated as delete plus add

### Merge semantics

The active policy engine is built from:

1. file-defined `cfg.Policies`
2. all active discovered policies from all policy discovery sources

This is additive, not replacement-based.

### Collision policy

Policy names must be globally unique across:

- file-defined policies
- all discovered policies from all remote sources

If a candidate snapshot introduces a duplicate policy name, the candidate
snapshot is rejected and the previously active discovered snapshot remains in
place.

This is stricter than last-writer-wins precedence and is intentional. Policy
overrides by duplicate name are hard to reason about and would make tenant
ownership ambiguous.

## Failure Handling

### Startup

Process startup should continue when:

- file-defined policies are valid, and
- remote policy discovery sources are configured but not yet reachable

This preserves the current safety model for local or bootstrap operation while
allowing remote sources to converge later.

If there are no file-defined policies and no previously fetched remote
policies, the existing runtime rule still applies: startup must not leave Aegis
running without any compiled policies.

### Poll failures

A failed poll must not clear the last-good discovered state.

Failure cases include:

- list failure
- object read failure
- YAML decode failure
- resource validation failure
- duplicate discovered policy names
- duplicate file/discovered policy names
- compile failure in the merged policy engine

In each case:

- log the failure with source details
- increment failure metrics
- keep serving with the previous active discovered snapshot

### Config reload

When the config file is reloaded:

- removed `discovery.policies[]` entries drop their discovered snapshots
- changed entries are rebuilt under the new generation
- unchanged entries still get rebuilt because they belong to the new generation
  context

The generation boundary keeps lifecycle management simple and matches the
existing reload design.

## Runtime Integration

The runtime manager should own discovered-policy snapshots separately from the
static `config.Config` value loaded from disk.

Suggested shape:

- keep the file config as the immutable base of the generation
- maintain an in-memory map of active remote snapshots keyed by discovery
  source name
- on each successful poll update, rebuild the merged policy set and compile a
  new policy engine
- swap only the policy-related runtime state under lock instead of rebuilding
  listeners

This reuses the existing generation-swap approach without requiring every
remote policy update to simulate a full file reload.

## Observability

Add metrics for remote policy discovery, at minimum:

- poll attempts by source and provider
- poll failures by source, provider, and stage
- active discovered policy count
- active discovered object count
- snapshot apply successes and failures
- last successful poll timestamp per source

Add structured logs with:

- source name
- provider
- bucket
- prefix
- object URI
- document identity
- failure stage

The existing admin simulation and policy evaluation paths should continue to
operate on the merged in-memory policy engine without special-case logic.

## Testing

Required coverage:

- config validation for `discovery.policies[]`
- provider construction for `aws`, `gcp`, and `azure`
- parser coverage for:
  - single-document object
  - multi-document object
  - empty YAML separator handling
  - invalid document rejection
- normalization from `ProxyPolicy` resource into `config.PolicyConfig`
- merge and duplicate-name handling across file and discovered policies
- diff behavior for:
  - add
  - update
  - object deletion
  - single-document removal from a multi-document object
- runtime behavior for:
  - successful poll updates active policy state
  - failed poll preserves last-good state
  - removed discovery source drops remote policies after config reload

Tests should use fakes for object-store listing and reads. No test should
require live cloud services.

## Example Rollout

The shipped example config should continue to show `policies: []` locally and
add commented examples for `discovery.policies[]`.

The README should document:

- additive merge semantics
- remote policy resource format
- multi-document YAML support
- ambient auth behavior in AWS, GCP, and Azure
- duplicate-name rejection
- last-good-state behavior on poll failure

## Success Criteria

This slice is complete when:

- Aegis can poll S3, GCS, and Azure Blob prefixes in the background
- discovered `ProxyPolicy` resources are merged with file-defined policies
- multi-document YAML objects are supported
- deletions in remote storage remove policies from active memory state
- failed polls do not wipe the last-good discovered policy snapshot
- duplicate policy names across all sources are rejected
- the merged policy engine updates without restarting listeners
- repository tests pass and docs/examples are updated
