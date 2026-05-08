# Aegis Policy Decision Implementation Plan

## Goal

Deepen `internal/policy` so proxy and runtime consume a normalized operational outcome instead of rebuilding policy semantics from `policy.Decision`.

## Task 1: Add policy operational outcomes

### Scope

- `internal/policy/engine.go`
- `internal/policy/engine_test.go`

### Changes

Add normalized outcome types and evaluation helpers that include:

- action and reason
- policy and rule metadata
- requested and effective TLS mode
- audit / would-* fields
- bypass and matched-policy metadata where still useful

Keep the existing raw `Decision` API temporarily if needed for a staged migration, but make the new outcome API authoritative for caller behavior.

### Tests

Add focused policy-level tests for:

- HTTP allow / deny
- unknown identity deny
- unknown identity audit
- bypass would-deny
- audit mode would-deny / would-allow
- CONNECT requested vs effective TLS mode
- CONNECT audit/bypass forcing effective passthrough

## Task 2: Switch proxy and runtime to policy outcomes

### Scope

- `internal/proxy/server.go`
- `internal/proxy/request_flow.go`
- `internal/proxy/observability.go`
- `internal/proxy/server_test.go`
- `internal/runtime/runtime.go`

### Changes

Update proxy request-flow evaluation to:

- call the new policy outcome API
- stop deriving shadow/audit/unknown-identity semantics from raw `policy.Decision`
- keep ownership only of connection limits and MITM runtime availability checks

Update runtime simulation to:

- call the new policy outcome API
- populate response fields directly from the normalized outcome
- stop rebuilding audit / would-* / unknown-identity logic inline

### Tests

Keep existing proxy/runtime regression coverage green and add/adjust focused tests only where the integration seam changes.

## Task 3: Clean up and verify

### Changes

- remove no-longer-needed caller-side semantic helpers if they become dead
- keep any compatibility bridge only if it still serves a real internal caller

### Verification

- `/usr/local/go/bin/go test ./internal/policy`
- `/usr/local/go/bin/go test ./internal/proxy ./internal/runtime ./cmd/aegis`
- `/usr/local/go/bin/go test ./...`

### Review

- spec compliance review for candidate 3
- code review focused on caller-side semantic leakage and test gaps
