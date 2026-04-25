# Aegis Discovery Registry And Explicit Policy Binding Design

## Goal

Redesign Aegis discovery and policy configuration so:

- Kubernetes discovery can authenticate natively against EKS, GKE, and AKS
  using the machine or workload identity of the host where Aegis runs.
- `kubeconfig` remains available for local development and ad hoc use.
- Discovery becomes an explicit central registry of named providers.
- Policies bind explicitly to discovery providers by name instead of matching
  all resolved identities globally by label.
- Kubernetes policy subjects select workloads through exact namespaces plus a
  shared `matchLabels` selector across one or more named Kubernetes providers.
- EC2 policy subjects bind only to named EC2 discovery providers.

This removes the current ambiguity where a label-only selector such as
`team=frontend` can unintentionally match pods from multiple clusters and EC2
instances at the same time.

## Scope

In scope:

- Extend `discovery.kubernetes[]` with pluggable auth modes:
  - `kubeconfig`
  - `inCluster`
  - `eks`
  - `gke`
  - `aks`
- Keep `discovery.ec2[]` as a named registry entry.
- Replace policy-wide `identitySelector` with explicit `subjects`.
- Make provider binding a required first step in policy matching.
- Update runtime provider construction for the new Kubernetes auth modes.
- Update docs, examples, validation, and tests.

Out of scope:

- Backward-compatible parsing of the old and new policy schemas together.
- Any change to EC2 discovery mechanics beyond explicit provider binding.
- External secret management or cloud-specific credential bootstrap beyond the
  machine/workload identity flows already provided by the relevant SDKs.
- New policy dimensions beyond provider binding, namespaces, and `matchLabels`.

## Config Shape

### Discovery Registry

Discovery remains the central registry of named providers:

```yaml
discovery:
  kubernetes:
    - name: cluster-a
      auth:
        provider: eks
        region: eu-central-1
        clusterName: cluster-a

    - name: cluster-b
      auth:
        provider: gke
        project: prod-project
        location: europe-west1
        clusterName: cluster-b

    - name: cluster-c
      auth:
        provider: aks
        subscriptionID: 00000000-0000-0000-0000-000000000000
        resourceGroup: rg-platform
        clusterName: cluster-c

    - name: dev
      auth:
        provider: kubeconfig
        kubeconfig: /path/to/kubeconfig
        context: dev
      namespaces: ["default"]
      resyncPeriod: 30s

  ec2:
    - name: legacy-web
      region: eu-central-1
      tagFilters:
        - key: role
          values: ["frontend"]
```

Each discovery entry keeps `name` as the stable reference key used by policy.

### Kubernetes Auth Modes

Each `discovery.kubernetes[]` entry gets an `auth` block with a required
`provider` field:

- `kubeconfig`
  - `kubeconfig` required
  - `context` optional
- `inCluster`
  - no extra required fields
- `eks`
  - `region` required
  - `clusterName` required
- `gke`
  - `project` required
  - `location` required
  - `clusterName` required
- `aks`
  - `subscriptionID` required
  - `resourceGroup` required
  - `clusterName` required

The intent is that Aegis acquires credentials through the ambient execution
identity of its environment:

- EKS: IAM role / instance profile / workload identity recognized by the AWS
  SDK and used to obtain cluster connection details and a Kubernetes bearer
  token through the native AWS path.
- GKE: Google application default credentials / workload identity recognized by
  the Google client path and used to obtain cluster connection details and
  access tokens.
- AKS: Azure managed identity / workload identity recognized by the Azure
  client path and used to obtain cluster connection details and access tokens.

`kubeconfig` remains the development-oriented path.

### Policies

Policies stop selecting identities globally via `identitySelector`. Instead
they declare explicit provider-scoped subjects:

```yaml
policies:
  - name: frontend-egress
    subjects:
      kubernetes:
        discoveryNames: ["cluster-a", "cluster-b"]
        namespaces: ["frontend"]
        matchLabels:
          app: frontend
      ec2:
        discoveryNames: ["legacy-web"]
    egress:
      - fqdn: "api.stripe.com"
        ports: [443]
        tls:
          mode: passthrough
```

Policy rollout controls remain unchanged:

- global `proxy.enforcement: audit|enforce`
- per-policy `enforcement: audit|enforce`
- per-policy `bypass: true`

## Runtime Semantics

### Discovery

Discovery providers remain ordered runtime components created from the
registry. Their `name` continues to be the stable provider identifier stored in
resolved identities.

Kubernetes runtime construction changes from:

- local `kubeconfig`, or
- generic `inCluster`

to:

- `kubeconfig`
- `inCluster`
- `eks`
- `gke`
- `aks`

Each auth mode produces a Kubernetes REST config for the named cluster, then
reuses the existing informer-based Kubernetes provider.

### Policy Matching

Policy evaluation becomes provider-scoped before any label matching:

1. Resolve the request source IP into an identity.
2. Inspect the identity source and provider name.
3. For Kubernetes identities:
   - the provider name must be listed in
     `subjects.kubernetes.discoveryNames`
   - the namespace label must match one of
     `subjects.kubernetes.namespaces`
   - identity labels must satisfy `subjects.kubernetes.matchLabels`
4. For EC2 identities:
   - the provider name must be listed in `subjects.ec2.discoveryNames`
5. If the identity does not match any subject block in the policy, the policy
   does not apply.
6. If the identity matches the subject, egress rule evaluation works exactly as
   today.

This makes policy scope explicit:

- a pod from `cluster-a` can be treated differently from an identical pod from
  `cluster-b`
- EC2 identities do not accidentally participate in Kubernetes label matching
- one policy can intentionally cover multiple clusters with one shared workload
  selector

### Kubernetes Subject Semantics

The Kubernetes subject selector is deliberately narrow:

- `discoveryNames` is a list of exact provider names
- `namespaces` is a list of exact namespace names
- `matchLabels` is an exact key/value selector

Wildcard or regex namespace selection is out of scope.

### EC2 Subject Semantics

EC2 policy subjects are intentionally provider-only. There is no EC2
`matchLabels` selector in this slice because the current system does not expose
an equivalent operator-facing workload selector model for instances.

## Validation

Validation must be strict and fail fast:

- every discovery entry name must be unique across all discovery kinds
- every Kubernetes auth block must declare a supported `provider`
- provider-specific auth fields must be present for the selected auth provider
- `subjects.kubernetes.discoveryNames` must reference existing Kubernetes
  discovery entries
- `subjects.ec2.discoveryNames` must reference existing EC2 discovery entries
- Kubernetes subject namespace entries must be non-empty exact names
- mixed old and new policy selector schemas are rejected
- policies that define no subjects are invalid
- policies may define one or both of:
  - `subjects.kubernetes`
  - `subjects.ec2`

## Compatibility And Migration

This is a meaning-changing config redesign. The implementation should not try to
quietly reinterpret the old policy selector model.

Migration approach:

- introduce the new schema
- reject the legacy `identitySelector` form once the new schema lands
- update `aegis.example.yaml`, Helm values, README examples, and validation
  error messages so the migration path is explicit

`kubeconfig` support remains available for development and local testing.

## Testing

Required coverage:

- config validation for every Kubernetes auth provider mode
- runtime provider construction tests for:
  - `kubeconfig`
  - `inCluster`
  - `eks`
  - `gke`
  - `aks`
- policy engine tests proving provider binding precedence:
  - identical pod labels in `cluster-a` and `cluster-b`
  - policy bound to `cluster-a` does not match `cluster-b`
  - one policy bound to both clusters with a shared selector matches both
  - EC2 provider binding works independently of Kubernetes selectors
- docs and example tests stay aligned with the new schema

Cloud-provider tests should mock the auth/client-building path instead of
making real cloud API calls.

## Implementation Notes

The design should preserve the existing strengths of the runtime:

- discovery remains a central registry with stable names
- multiple providers of the same kind remain supported
- first configured provider still wins at identity-resolution time
- overlap metrics remain valuable and should continue to work
- policy rollout controls remain unchanged

The key behavioral change is not in discovery resolution itself. It is in how
policies bind to the identities returned by discovery: explicit provider scope
first, then Kubernetes namespace and label selection where relevant.
