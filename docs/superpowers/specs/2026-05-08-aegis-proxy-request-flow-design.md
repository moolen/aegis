# Aegis Proxy Request Flow Design

**Date:** 2026-05-08
**Status:** Approved for implementation

## Goal

Deepen the proxy request-flow module so `internal/proxy/server.go` stops owning
policy, audit, transport, MITM, and observability concerns all at once.

This slice keeps the public `proxy.NewServer(deps)` seam stable while moving
most behavior behind smaller internal modules with better locality and
testability.

## Scope

### In scope

- Split `internal/proxy/server.go` into smaller runtime-owned files within the
  same `internal/proxy` package.
- Introduce a normalized request-flow decision seam used by HTTP, CONNECT, and
  MITM request paths.
- Separate plain HTTP forwarding, CONNECT tunneling, MITM session handling, and
  observability helpers into focused modules.
- Preserve current policy, audit, MITM, logging, and metrics behavior.
- Keep existing public constructors and dependency types stable.
- Add focused tests around the new request-flow seam while preserving the
  current end-to-end proxy regression tests.

### Out of scope

- Changing policy engine semantics.
- Changing identity resolver behavior.
- Changing admin/runtime wiring outside `internal/proxy`.
- Introducing new public proxy packages.
- Changing metrics schemas or log field vocabulary.

## Design Boundary

This refactor changes where proxy behavior lives, not what the Aegis proxy
does.

The shipped proxy must still:

- evaluate identity and policy before forwarding,
- enforce unknown-identity deny behavior,
- support global audit and policy-level audit/bypass,
- enforce per-identity connection limits,
- protect destinations through DNS and direct-IP guards,
- support CONNECT passthrough and CONNECT MITM,
- preserve current logging and metrics behavior.

The change is architectural: transport code should stop reconstructing policy
and audit behavior independently.

## Module Shape

Keep one public package: `internal/proxy`.

Split the implementation into focused internal modules:

- `server.go`
  Thin entrypoint and top-level HTTP vs CONNECT dispatch only.
- `request_flow.go`
  Owns request parsing, identity lookup, policy evaluation, audit/shadow
  handling, unknown-identity handling, connection-limit acquisition, and the
  normalized flow result.
- `http_flow.go`
  Owns plain HTTP forwarding after a request-flow decision has already allowed
  the request.
- `connect_flow.go`
  Owns CONNECT tunnel establishment, SNI inspection, passthrough setup, and
  CONNECT-mode transport behavior.
- `mitm_flow.go`
  Owns MITM TLS session setup and decrypted HTTP forwarding.
- `observability.go`
  Owns request decision logging and metric recording helpers.

Keep the public seam unchanged:

- `proxy.NewServer(deps)`
- `(*Server).Handler()`

## Core Seam

The load-bearing module is a normalized request-flow decision.

Today, `handleHTTP`, `handleConnect`, and `handleMITMHTTPRequest` reconstruct
the same policy logic repeatedly:

- identity resolution,
- unknown-identity deny,
- policy evaluation,
- audit/shadow handling,
- effective TLS mode,
- logging inputs,
- metrics inputs.

Introduce a private flow result that captures those decisions once.

The flow result should include at minimum:

- protocol,
- target host and port,
- request identity,
- policy decision,
- audit outcome,
- effective action (`allow` or `deny`),
- deny reason,
- effective CONNECT mode,
- whether MITM inspection is required,
- whether shadow mode forces passthrough,
- acquired connection-limit release hook when applicable.

The rule is:

1. Parse target.
2. Evaluate request-flow once.
3. If denied, emit normalized metrics/logs/error response.
4. If allowed, hand off to the transport-specific module.

This makes the request-flow interface the test surface instead of scattering
policy behavior across multiple transport paths.

## HTTP Flow

`http_flow.go` should only own plain HTTP transport behavior after a request
has been allowed:

- resolve destination address,
- block forbidden resolved destinations,
- build the outbound request,
- perform the upstream round trip,
- copy response headers/body,
- translate upstream transport errors into the current proxy responses.

It should not decide whether the request is allowed. That decision must already
be encoded in the flow result.

## CONNECT Flow

`connect_flow.go` should own CONNECT transport behavior after the request-flow
decision:

- decide whether passthrough or MITM transport applies from the normalized flow
  result,
- resolve the CONNECT destination,
- establish the upstream TCP connection when needed,
- hijack the client connection,
- read and validate the TLS ClientHello,
- enforce SNI match,
- hand off to either passthrough tunnel splicing or MITM flow.

CONNECT transport should stop recomputing policy/audit logic inline.

## MITM Flow

`mitm_flow.go` should own:

- client-side forged certificate handshake,
- single-use MITM listener lifecycle,
- decrypted HTTP request forwarding,
- MITM-specific upstream TLS handshake and response copying.

MITM decrypted HTTP requests should still consume the same request-flow seam so
policy behavior stays centralized even after the initial CONNECT decision.

## Observability Ownership

`observability.go` should own:

- request decision logging,
- audit logging helpers,
- metric recording helpers for decisions, errors, TLS outcomes, and connect
  results,
- shared normalization helpers for policy and identity names.

This keeps transport modules focused on behavior instead of metric/log
bookkeeping.

## Rollout Strategy

This should be implemented as a staged internal split, not a rewrite.

Recommended order:

1. Introduce the request-flow result and move policy/audit logic behind it.
2. Update `handleHTTP`, `handleConnect`, and MITM request handling to consume
   that result without changing behavior.
3. Split HTTP forwarding into `http_flow.go`.
4. Split CONNECT transport into `connect_flow.go`.
5. Split MITM logic into `mitm_flow.go`.
6. Move logging/metrics helpers into `observability.go`.
7. Thin `server.go` to mostly top-level dispatch and constructor logic.

This order keeps the existing regression net intact while increasing depth
incrementally.

## Testing Strategy

Keep the current proxy end-to-end tests as the regression net.

Add focused tests for the new request-flow seam covering:

- unknown-identity deny vs audit behavior,
- policy deny vs allow behavior,
- policy-level audit behavior,
- bypass behavior,
- CONNECT mode resolution: passthrough vs MITM,
- connection-limit denial,
- normalized deny reasons and audit outcomes.

Transport tests should then focus on transport behavior after evaluation:

- HTTP forwarding and upstream error translation,
- CONNECT tunnel establishment and SNI enforcement,
- MITM session behavior and decrypted request forwarding.

The design is successful if policy and audit behavior no longer need to be
re-proved independently in every transport test.

## Success Criteria

This slice is complete when:

- `internal/proxy/server.go` is reduced to a thin entrypoint and dispatch
  module,
- request-flow evaluation is centralized behind one private seam,
- HTTP, CONNECT, and MITM transport paths consume that seam instead of
  rebuilding policy logic inline,
- observability helpers no longer dominate transport files,
- existing proxy behavior is preserved,
- repository tests and builds pass after the refactor.
