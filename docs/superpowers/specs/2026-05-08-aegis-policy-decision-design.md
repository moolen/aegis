# Aegis Policy Decision Module Design

## Summary

The current `internal/policy` module returns a thin `Decision` describing raw policy match state:

- `Allowed`
- `Policy`
- `Rule`
- `TLSMode`
- `Bypass`
- `PolicyEnforcement`

That leaves the real operational behavior to callers. Both `internal/proxy/request_flow.go` and `internal/runtime/runtime.go` reconstruct:

- unknown-identity deny vs audit behavior
- audit/shadow semantics
- allow/deny reason strings
- would-allow / would-deny outcomes
- effective CONNECT TLS mode
- policy-bypass reporting

This makes the policy module shallow. Callers still need policy-specific knowledge to decide what the proxy or simulation should do.

This refactor deepens the module by moving those semantics into `internal/policy`, so callers consume one operational outcome instead of rebuilding behavior from raw policy fields.

## Problem

The current shape leaks policy semantics across module boundaries:

1. `internal/policy` answers “what matched”.
2. Proxy/runtime answer “what should happen”.

That split has three costs:

- **Low locality**: changes to enforcement behavior require coordinated edits across `internal/policy`, `internal/proxy`, and `internal/runtime`.
- **Low leverage**: tests for policy behavior sit in caller modules instead of behind one policy interface.
- **Semantic drift risk**: proxy and runtime can diverge in how they interpret bypass, audit, unknown identities, and TLS mode.

## Goal

Make `internal/policy` the authoritative owner of policy enforcement semantics.

Callers should receive one normalized operational outcome that already answers:

- allow or deny
- why
- what would have happened under audit/bypass semantics
- what CONNECT TLS mode should be requested and effectively enforced

The proxy should keep ownership only of concerns that are not policy semantics:

- request parsing
- identity lookup
- connection limiting
- MITM runtime availability checks
- transport handling

The runtime simulation path should stop reconstructing shadow/audit logic itself and should render policy outcomes directly.

## Non-Goals

- Moving identity resolution into `internal/policy`
- Moving connection-limit semantics into `internal/policy`
- Moving MITM engine availability checks into `internal/policy`
- Changing the existing policy matching model or config format

## Proposed Design

### Public API

Replace the thin `Decision`-only surface with protocol-aware operational evaluation methods.

Representative shape:

```go
type EvaluateInput struct {
    Identity              *identity.Identity
    SourceIP              netip.Addr
    FQDN                  string
    Port                  int
    Method                string
    Path                  string
    Protocol              string
    EnforcementMode       string
    UnknownIdentityPolicy string
}

type Outcome struct {
    Action           string
    Reason           string
    Policy           string
    Rule             string
    RequestedTLSMode string
    EffectiveTLSMode string
    Audit            AuditOutcome
    Matched          bool
}

type AuditOutcome struct {
    Enabled      bool
    WouldAction  string
    WouldReason  string
    WouldBlock   bool
    PolicyBypass bool
}
```

Concrete method shape can stay as one method or two protocol-specific methods:

- `EvaluateHTTP(input) Outcome`
- `EvaluateConnect(input) Outcome`

The important constraint is not the exact type names. The important constraint is that callers stop deriving operational semantics from raw decision fields.

### Outcome Semantics

The policy module should normalize these cases:

- `unknown_identity`
- `policy_denied`
- `policy_allowed`
- `audit_unknown_identity`
- `audit_policy_denied`
- `audit_policy_allowed`

For CONNECT, the outcome should also distinguish:

- `RequestedTLSMode`
  The TLS mode requested by the matched policy rule.
- `EffectiveTLSMode`
  The TLS mode that should be applied after policy semantics are resolved.

Examples:

- normal allow with `mitm` rule:
  - `Action=allow`
  - `Reason=policy_allowed`
  - `RequestedTLSMode=mitm`
  - `EffectiveTLSMode=mitm`

- audit/bypass allow with `mitm` rule:
  - `Action=allow`
  - `Reason=audit_policy_denied` or `audit_policy_allowed`
  - `RequestedTLSMode=mitm`
  - `EffectiveTLSMode=passthrough`

- unknown identity in audit mode:
  - `Action=allow`
  - `Reason=audit_unknown_identity`
  - `WouldAction=would_deny`
  - `WouldReason=unknown_identity`

### Caller Ownership After Refactor

After this change:

- `internal/policy` owns:
  - policy match evaluation
  - unknown identity semantics
  - audit/bypass/shadow semantics
  - allow/deny reason normalization
  - requested/effective CONNECT TLS mode

- `internal/proxy` owns:
  - request/target parsing
  - identity lookup
  - connection limit enforcement
  - MITM engine presence validation
  - transport execution

- `internal/runtime` owns:
  - simulation request parsing
  - identity lookup for simulation
  - rendering the already-computed policy outcome in API responses

## Module Changes

### `internal/policy`

Add:

- protocol-aware operational outcome types
- helper logic that converts raw policy matches into caller-ready outcomes
- tests for:
  - unknown identity deny vs audit
  - bypass semantics
  - audit policy deny vs allow
  - CONNECT requested/effective TLS mode

Keep temporarily during migration:

- raw `Decision` support if needed for a staged rollout

### `internal/proxy`

Simplify `request_flow.go` so it:

1. resolves request target
2. resolves request identity
3. asks policy for an operational outcome
4. applies non-policy runtime constraints:
   - connection limits
   - MITM configured or not

Proxy should stop computing:

- `shadow`
- audit outcomes
- unknown identity policy handling
- policy deny/allow reasons
- effective CONNECT TLS mode

### `internal/runtime`

Simplify simulation logic so it:

- requests a policy outcome
- maps it directly into `SimulationResponse`

Runtime should stop recomputing:

- `shadow`
- `WouldAction`
- `WouldReason`
- `WouldBlock`
- unknown identity audit behavior

## Rollout Plan

1. Add operational outcome types and evaluation helpers in `internal/policy`.
2. Add policy tests covering normalized operational semantics.
3. Update `internal/proxy` to consume policy outcomes while preserving current behavior.
4. Update `internal/runtime` simulation to consume policy outcomes.
5. Remove no-longer-needed caller-side policy semantic helpers.
6. Keep regression coverage in proxy/runtime green while moving focused semantic tests into `internal/policy`.

## Testing Strategy

### New Policy-Level Tests

Add focused tests in `internal/policy` for:

- HTTP allow
- HTTP deny
- unknown identity deny
- unknown identity audit
- bypass would-deny semantics
- audit-mode would-deny semantics
- CONNECT allow with passthrough
- CONNECT allow with MITM requested/effective mode
- CONNECT audit/bypass mode forcing effective passthrough

### Caller Regression Coverage

Keep existing proxy/runtime tests to verify integration behavior:

- HTTP request decisions remain unchanged
- CONNECT mode behavior remains unchanged
- MITM behavior remains unchanged
- runtime simulation output remains unchanged

The goal is to move semantic unit coverage down into `internal/policy`, not to weaken integration coverage.

## Expected Benefits

- **Better locality**: policy enforcement changes land mainly in `internal/policy`
- **Deeper module**: callers consume outcomes, not raw match ingredients
- **Stronger tests**: semantic behavior can be asserted once at the policy seam
- **Less duplication**: proxy and runtime stop rebuilding the same logic
- **Lower drift risk**: one module defines what policy decisions mean operationally

## Acceptance Criteria

- Proxy no longer computes shadow/audit/unknown-identity policy semantics itself.
- Runtime simulation no longer reconstructs policy semantics itself.
- `internal/policy` has focused tests for operational outcomes.
- Existing proxy/runtime behavior remains green under `go test ./...`.
