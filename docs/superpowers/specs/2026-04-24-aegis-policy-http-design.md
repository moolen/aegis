# Aegis Plain HTTP Policy Enforcement Design

**Date:** 2026-04-24
**Status:** Approved for implementation

## Goal

Implement the first full product slice on top of the MVP bootstrap: policy-aware
plain HTTP proxying.

This slice adds the real policy config model, a policy evaluation engine, and
request-time enforcement for non-`CONNECT` proxy traffic. It deliberately stops
short of Kubernetes/EC2 discovery, CONNECT TLS inspection, and MITM support.

## Scope

### In scope

- Extend the config schema to support policy definitions and validation.
- Implement a real `internal/policy` engine.
- Expand identity types just enough to support stable request-time identity
  objects and test resolvers.
- Enforce allow/deny decisions for plain HTTP proxy requests before DNS lookup
  and upstream dialing.
- Add unit and integration-style tests for policy semantics and proxy
  enforcement.
- Update documentation and example config to reflect the new behavior.

### Out of scope

- Kubernetes informer-based identity discovery.
- EC2 polling-based identity discovery.
- Request identity extraction from real source IPs.
- CONNECT SNI parsing and validation.
- MITM certificate generation and TLS interception.
- HTTP policy enforcement inside TLS tunnels.

## Design Boundary

This subproject is limited to plain HTTP requests handled through the forward
proxy path. The existing `CONNECT` path remains structurally unchanged for now.

The proxy must become policy-aware for standard HTTP proxy requests that arrive
with absolute URLs. Those requests must be evaluated against configured
policies, and denied requests must return `403 Forbidden` without DNS lookup or
upstream dial attempts.

## Configuration Model

The bootstrap config model is extended with a top-level `policies` list using
the final unified-label shape from the main design draft.

Each policy contains:

- `name`
- `identitySelector.matchLabels`
- ordered `egress` rules

Each egress rule contains:

- `fqdn`
- `ports`
- `tls.mode`
- optional `http.allowedMethods`
- optional `http.allowedPaths`

### Validation rules

Config validation must enforce:

- every policy has a non-empty name,
- every egress rule has an `fqdn`,
- every egress rule declares at least one valid port,
- `tls.mode` is either `mitm` or `passthrough`,
- `http` rules are only valid when `tls.mode` is `mitm`,
- HTTP method/path lists do not contain empty entries.

Even though this slice does not use TLS mode operationally for plain HTTP, the
config schema should validate it now so the repository converges toward the
final shape instead of carrying a temporary policy format.

## Identity Model

The identity package should keep the long-term `Identity` type, but the
bootstrap implementation only needs enough functionality to support policy
evaluation in-process.

Key behavior:

- request handling receives an `*identity.Identity`,
- if no resolver is configured or no identity is available, the request is
  evaluated as `unknown`,
- an unknown identity has no labels unless a caller explicitly provides them.

This lets tests inject stable label sets without introducing Kubernetes or EC2
code prematurely.

## Policy Engine

The policy engine must implement the final evaluation semantics for this slice:

- policies are evaluated in declaration order,
- first matching policy wins,
- policy selector match requires all configured labels to match exactly,
- within the matched policy, at least one egress rule must match,
- an egress rule matches on FQDN glob plus port,
- if HTTP rules are present, method and path must also match,
- if no policy or no egress rule matches, the request is denied.

### Matching semantics

- FQDN matching uses simple glob semantics where `*` can match across label
  components, e.g. `*.example.com` matches `api.example.com`.
- Path matching uses the same glob semantics.
- Method matching is exact and case-insensitive after normalizing to upper case.
- Selector matching is exact on key/value pairs.

### Decision shape

The engine should return a decision object that includes:

- `Allowed`
- `Policy`
- `Rule`
- `TLSMode`

That decision object becomes the stable contract the proxy can use later for
CONNECT, SNI, and MITM work.

## Proxy Integration

Plain HTTP request flow becomes:

1. Parse absolute target URL.
2. Resolve request identity through a lightweight resolver interface.
3. Evaluate policy using identity, target host, port, method, and path.
4. If denied, return `403 Forbidden`.
5. If allowed, continue with DNS lookup and upstream round trip.

Important constraints:

- Denied requests must not trigger DNS resolution.
- Denied requests must not attempt an upstream connection.
- Existing bootstrap `CONNECT` behavior remains unchanged in this slice.

## Error Handling

This slice introduces one new user-visible failure mode:

- policy deny for plain HTTP requests returns `403 Forbidden`.

Malformed requests and infrastructure failures keep the existing semantics:

- malformed request: `400`
- DNS / upstream dial failure: `502`
- internal failure: `500`

## Testing Strategy

### Unit tests

`internal/policy` tests must cover:

- exact selector matching,
- unknown identity behavior,
- first-match-wins ordering,
- FQDN glob matching,
- port matching,
- method restriction,
- path restriction,
- deny when no rule matches.

`internal/config` tests must cover:

- valid policy config,
- invalid TLS mode,
- invalid `http` + `passthrough` combinations,
- empty required fields.

### Proxy tests

`internal/proxy` tests must cover:

- allowed plain HTTP request reaches upstream,
- denied plain HTTP request returns `403`,
- denied plain HTTP request does not hit upstream,
- denied plain HTTP request does not trigger DNS lookup.

Tests may use static resolvers and static identities. There is no need to add
cross-process or cluster-aware end-to-end coverage in this slice.

## Documentation Updates

Update:

- `aegis.example.yaml` to include a minimal policy example,
- `README.md` to explain that plain HTTP requests are now policy-enforced while
  `CONNECT` remains bootstrap-grade,
- any package comments or docs that still imply the repo is only a generic
  proxy.

## Success Criteria

This slice is complete when:

- policy config can be loaded and validated,
- the policy engine returns correct decisions for HTTP requests,
- plain HTTP proxy traffic is denied or allowed according to policy,
- denied HTTP requests short-circuit before DNS/upstream work,
- tests pass,
- documentation matches the implemented behavior.
