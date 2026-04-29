# Aegis Azure Cloud E2E Integration Design

## Summary

This spec defines a Go end-to-end integration suite that runs against a
preprovisioned Azure environment and validates the full cloud control loop for
Aegis:

- AKS pod and namespace discovery
- Azure Blob-backed remote policy discovery
- live authorization changes in the Aegis data plane

The suite assumes the base Azure infrastructure already exists and that the test
runner has exclusive control of one Blob policy prefix and the test namespaces
it creates in AKS.

## Goals

- Verify that AKS pod lifecycle changes are reflected in Aegis authorization
  without manual intervention.
- Verify that AKS namespace lifecycle and namespace-scoped policy subjects are
  reflected in Aegis authorization.
- Verify that Azure Blob object create, update, and delete operations propagate
  into Aegis remote policy state.
- Verify these changes through the real private network path:
  `AKS workload -> Aegis ACI -> private NGINX VM`.
- Produce actionable diagnostics when reconciliation or propagation fails.

## Non-Goals

- Provision or destroy Azure infrastructure from the test suite.
- Cover internet egress targets.
- Replace the existing shell-based perf harness.
- Validate multi-tenant safety in a shared Azure test environment.

## Preconditions

The suite requires a preprovisioned Azure environment with:

- an AKS cluster reachable by the test runner
- two Aegis instances running as Azure Container Instances
- Azure Blob storage configured as an Aegis policy discovery source
- a private NGINX VM acting as the upstream target
- private DNS and routing already working for the Aegis and NGINX endpoints

The suite also assumes:

- the operator has already authenticated to Azure
- Kubernetes credentials for AKS are already configured
- the suite has exclusive control of the configured Blob prefix
- the suite may create and delete namespaces and workloads in AKS

## Test Strategy

The suite will live under `e2e/` as a Go integration test harness gated by a
dedicated build tag such as `cloud_e2e`.

It will use real clients, not shell wrappers, for the cloud control plane:

- `client-go` for AKS namespace, deployment, pod, and exec operations
- Azure Blob SDK for object create, update, list, and delete
- standard Go HTTP clients or in-cluster curl pods for data-plane probes

The suite will treat the Azure environment as immutable base infrastructure and
will own only ephemeral runtime state:

- test namespaces
- test workloads
- test Blob policy objects under a per-run prefix

## Harness Design

### Azure Harness Responsibilities

The Azure harness will:

- create a unique run identifier
- derive unique namespace names and Blob object names from that run identifier
- create and delete namespaces
- deploy and scale workload pods used for authorization probes
- upload, update, list, and delete Blob policy objects under the run prefix
- execute proxied requests from AKS pods through Aegis to the private NGINX VM
- poll Aegis metrics until expected convergence is reached on both Aegis
  instances
- dump diagnostics on failure

### Configuration

The suite will read its runtime inputs from environment variables rather than
embedding Terraform assumptions into the tests. Required inputs:

- `AEGIS_PROXY_URL`
- `AEGIS_TARGET_URL`
- `AEGIS_TARGET_HTTPS_URL`
- `AZURE_STORAGE_ACCOUNT_NAME`
- `AZURE_POLICY_CONTAINER`
- `AZURE_POLICY_PREFIX`
- `AEGIS_METRICS_ENDPOINTS`

Optional inputs:

- `CLOUD_E2E_NAMESPACE_PREFIX`
- `CLOUD_E2E_TIMEOUT`
- `CLOUD_E2E_POLL_INTERVAL`
- `CLOUD_E2E_KEEP_ARTIFACTS`

`AEGIS_METRICS_ENDPOINTS` will identify the Aegis metrics endpoints that the
tests must observe before declaring convergence. In the current Azure topology,
these are the private `:9090` endpoints for the ACI instances, reachable from
inside AKS.

### Convergence Model

Every test mutation must use poll-based convergence rather than fixed sleeps.
The suite will not treat a control-plane action as complete until both of the
following are true:

1. The expected data-plane behavior is observed from AKS test pods.
2. Both Aegis instances report the expected remote policy state metrics.

Blob mutations converge when both Aegis instances report the expected
`aegis_policy_discovery_policies_active` count for the Azure discovery source
and request behavior matches the expected authorization result.

Kubernetes mutations converge when new or updated pods exhibit the expected
allow/deny behavior and stale pods or deleted namespaces no longer retain
authorization unexpectedly.

## Scenario Coverage

### 1. Blob Policy Lifecycle Propagation

This scenario validates remote policy create, update, and delete.

Flow:

- start with no matching remote policy object for the workload
- verify proxied request is denied
- create an allow policy Blob object
- verify request becomes allowed
- update the policy to narrow the allowed path, namespace, or labels
- verify the previous request becomes denied and the new allowed request
  succeeds
- delete the Blob object
- verify the request returns to denied

Assertions:

- allow/deny transitions happen without Aegis restart
- policy discovery metrics converge on both Aegis instances
- Blob object listing under the test prefix matches the expected fixture set

### 2. Pod Scale and Identity Churn

This scenario validates that AKS pod changes reconfigure Aegis identity state.

Flow:

- create a namespace and deploy a matching workload with one replica
- verify traffic is allowed through Aegis
- scale the deployment up to multiple replicas
- verify new pods become authorized
- scale the deployment down
- verify deleted pod IPs do not remain authorized
- restart or recreate pods
- verify newly assigned pod IPs become authorized without manual reload

Assertions:

- authorization follows currently running pods
- deleted pods do not continue to receive authorization due to stale identity
  mappings
- replacement pods converge to allowed state using the same policy subject

### 3. Namespace Lifecycle and Subject Scope

This scenario validates namespace-based policy subject matching.

Flow:

- create namespace A with matching workload labels and no remote policy
- verify denied
- create remote policy that targets namespace A
- verify allowed in namespace A
- create namespace B with the same workload labels
- verify denied in namespace B while namespace A remains allowed
- update remote policy to include namespace B
- verify namespace B becomes allowed
- remove namespace A from the policy or delete namespace A
- verify namespace A no longer influences the effective authorization set

Assertions:

- namespace filters are enforced independently from labels
- updating namespace lists in Blob-backed policies propagates correctly
- namespace deletion does not leave stale authorization behind

### 4. Cross-Source Control Plane Convergence

This scenario validates that the Kubernetes identity provider and Azure policy
discovery provider agree on effective enforcement.

Flow:

- apply a policy that requires both a specific namespace and specific pod labels
- create a workload missing the label and verify denied
- patch the workload to add the matching label and verify allowed
- patch the workload to remove the label again and verify denied
- update the remote policy to change the namespace or label selector and verify
  the new effective state

Assertions:

- authorization changes only when the combined Kubernetes and Blob-backed state
  matches the policy
- both Aegis instances converge on the same policy snapshot before the test
  advances

## Test Fixtures

The suite will use simple, explicit fixtures:

- a small AKS client deployment for making proxied requests
- one or more probe pods with deterministic labels
- YAML policy fixtures generated per test with unique names under the test Blob
  prefix

Policies should remain minimal and focus on one behavioral variable per test:

- namespace matching
- label matching
- path matching
- object existence

This keeps failures attributable to one reconciliation path at a time.

## Diagnostics and Cleanup

Each test will create unique namespaces and Blob object names. On normal
completion, the suite will delete all test namespaces and Blob objects.

On failure, the suite will:

- capture pod lists, deployment status, and namespace events
- capture the current set of Blob objects under the active test prefix
- capture Aegis metrics from both Aegis instances
- capture recent Aegis log tails when available
- preserve enough state to explain whether the failure was in Kubernetes
  discovery, Blob discovery, or proxy enforcement

Cleanup must be best-effort and idempotent so that a failed run can be followed
by a new run using a different unique prefix.

## File Layout

Planned files:

- `e2e/cloud_suite_test.go`
- `e2e/cloud_helpers_test.go`
- `e2e/cloud_blob_policy_test.go`
- `e2e/cloud_identity_scale_test.go`
- `e2e/cloud_namespace_scope_test.go`
- `e2e/cloud_convergence_test.go`

Supporting documentation and tooling updates:

- `e2e/README.md`
- `deploy/azure/README.md`
- `Makefile`

## Risks and Mitigations

### Flakiness from Control Plane Latency

Mitigation:

- use poll-based convergence with explicit timeouts
- require both metrics convergence and data-plane convergence
- avoid fixed sleeps as success criteria

### Leaked Runtime State Between Test Runs

Mitigation:

- unique per-run namespace and Blob object names
- explicit cleanup for both Kubernetes and Blob objects
- optional keep-artifacts mode only for debugging

### Ambiguous Failures

Mitigation:

- dump Kubernetes diagnostics, Blob listings, and Aegis metrics together
- keep scenario responsibilities narrow so a failing test points to one class of
  reconciliation issue

## Success Criteria

The suite is successful when it can deterministically prove all of the
following against a preprovisioned Azure environment:

- Blob policy create, update, and delete operations propagate into Aegis
- AKS pod scale-up, scale-down, and recreation propagate into Aegis
- namespace addition, update, and deletion affect authorization correctly
- the real Azure data path behaves consistently with the discovered Kubernetes
  and Blob state
- failures emit enough diagnostics to support root-cause analysis without
  re-running the test blindly
