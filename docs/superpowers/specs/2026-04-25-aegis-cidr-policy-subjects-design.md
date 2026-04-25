# Aegis CIDR Policy Subjects Design

## Goal

Extend the explicit policy subject model so a policy can match directly on the
request source IP through inline CIDR ranges, without requiring discovery.

This allows operators to write policies for sources such as:

- office NAT ranges
- VPN ranges
- partner networks
- transition environments that are not yet covered by discovery

The new CIDR subject kind must fit cleanly into the already-approved subject
model based on explicit provider-scoped Kubernetes and EC2 bindings.

## Scope

In scope:

- add `subjects.cidrs` as a third policy subject kind
- match CIDRs directly against the request source IP
- combine Kubernetes, EC2, and CIDR subjects with OR semantics
- validate, normalize, and document CIDR subjects
- update tests and examples

Out of scope:

- named reusable CIDR sets
- CIDR negation
- AND/intersection logic between CIDR and discovery-backed subjects
- any change to discovery registry behavior
- any change to Kubernetes or EC2 subject semantics

## Config Shape

Policies gain an optional inline `subjects.cidrs` list:

```yaml
policies:
  - name: office-egress
    subjects:
      cidrs:
        - "10.20.0.0/16"
        - "203.0.113.0/24"
    egress:
      - fqdn: "api.example.com"
        ports: [443]
        tls:
          mode: passthrough
```

Mixed subject kinds remain valid:

```yaml
policies:
  - name: mixed-sources
    subjects:
      kubernetes:
        discoveryNames: ["cluster-a", "cluster-b"]
        namespaces: ["frontend"]
        matchLabels:
          app: frontend
      ec2:
        discoveryNames: ["legacy-web"]
      cidrs:
        - "10.50.0.0/16"
    egress:
      - fqdn: "api.stripe.com"
        ports: [443]
        tls:
          mode: passthrough
```

`subjects.cidrs` is always inline and policy-local in this slice.

## Runtime Semantics

Policy subject matching becomes:

- evaluate Kubernetes subject if present
- evaluate EC2 subject if present
- evaluate CIDR subject if present
- the policy applies if any configured subject kind matches

CIDR matching uses the actual request source IP and does not depend on identity
resolution.

This means:

- a CIDR-only policy can apply even when discovery is not configured
- a request may match a policy either through discovery-backed identity
  selection or through direct source-IP CIDR membership
- if no configured subject kind matches, the policy does not apply

The rest of policy evaluation is unchanged:

- once a policy subject matches, rule evaluation proceeds as today
- first matching policy still wins
- allow/deny, audit, bypass, and CONNECT semantics remain unchanged

## Validation

Validation must be strict and fail fast:

- every `subjects.cidrs` entry must be a valid CIDR
- empty CIDR strings are invalid
- CIDR entries should be normalized to canonical string form
- a policy must still define at least one subject overall
- mixed subject kinds remain valid
- IPv4 and IPv6 CIDRs are both supported if they parse successfully

There is no requirement for discovery when a policy uses only CIDR subjects.

## Architecture

The implementation should stay small and local:

- extend policy config with `subjects.cidrs`
- compile CIDR strings once into parsed prefixes
- change policy subject matching from identity-only to
  `matches(identity, sourceIP)`
- leave discovery registry and identity resolution behavior untouched

The main runtime contract change is that policy evaluation must have access to
the request source IP even when no identity resolves.

## Testing

Coverage should include:

- CIDR-only policies allow matching source IPs
- CIDR-only policies do not match non-member source IPs
- mixed Kubernetes/EC2/CIDR subjects use OR semantics
- invalid CIDRs fail config validation
- IPv4 CIDR matching
- IPv6 CIDR matching
- no-subject policies remain invalid

## Operator Guidance

CIDR subjects are intended for explicit non-discovery source ranges, not as a
replacement for discovery-backed workload selection.

Recommended usage:

- use Kubernetes subjects for discovered pod workloads
- use EC2 subjects for discovered instances
- use CIDR subjects for fixed network ranges and migration edges

This keeps discovery as the primary identity system while still supporting
well-bounded source-IP policying where needed.
