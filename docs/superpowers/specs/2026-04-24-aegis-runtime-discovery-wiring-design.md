# Aegis Runtime Discovery Wiring Design

**Date:** 2026-04-24
**Status:** Approved for implementation

## Goal

Wire configured discovery providers into the shipped Aegis process so proxy
requests can resolve real workload identities at runtime.

This slice turns the existing Kubernetes provider package into a runtime
feature, but stops before adding EC2 discovery or changing policy semantics.

## Scope

### In scope

- Build and start multiple configured discovery providers at process startup.
- Support multiple providers across discovery kinds and multiple entries of the
  same kind.
- Compose healthy providers behind a single ordered identity resolver.
- Pass the composite resolver into the proxy runtime.
- Expose discovery startup, overlap, and resolve behavior through metrics and
  logs.
- Fail startup only when discovery is configured but zero providers become
  active.

### Out of scope

- EC2 provider implementation.
- Dynamic config reload.
- Discovery hot-plugging.
- Policy-engine rule changes.
- CONNECT or TLS identity extraction changes.

## Design Boundary

This slice changes runtime startup and request-time identity resolution, but it
does not change the policy engine contract or add new provider kinds.

The shipped process must continue to start a single proxy listener and a single
metrics listener. The new behavior is that discovery providers are attempted at
startup and, if healthy, contribute to request identity resolution during plain
HTTP policy evaluation.

## Configuration Model

Use the existing `discovery` config section as the runtime source of truth.

For this slice, only `discovery.kubernetes` entries are constructible, but the
runtime wiring must be designed to support multiple provider kinds in a single
ordered list later.

Provider precedence is config order across all discovery entries. The first
configured provider that matches an IP wins.

## Runtime Architecture

### Provider startup orchestration

`cmd/aegis/main.go` should:

- iterate through configured discovery entries in config order,
- attempt to build and start each provider,
- retain healthy providers in that same order,
- log startup or sync failures with provider name and kind,
- increment discovery startup failure metrics for failed providers,
- continue process startup as long as at least one configured provider becomes
  active.

If discovery is configured and no providers become active, process startup must
fail.

If discovery is not configured, startup should proceed with the existing
unknown-identity fallback behavior.

### Composite resolver

Add a composite resolver in `internal/identity` that owns an ordered list of
providers and implements the existing resolver contract.

On `Resolve(ip)`:

- query providers in config order,
- remember the first non-`nil` identity as the winner,
- continue checking later providers so overlaps can be detected,
- if later providers also return a non-`nil` identity, keep the first result
  and increment an overlap metric,
- if a provider returns an error, log it, increment a resolve-error metric, and
  continue,
- if no providers match, return `nil`.

This keeps precedence deterministic while preserving observability for ambiguous
source IP ownership.

### Provider abstraction

Providers used by the composite should expose:

- `Start(ctx) error`
- `Resolve(ip net.IP) (*Identity, error)`

Startup behavior belongs in the orchestration layer, not in the composite. The
composite only resolves identities using already-active providers.

## Metrics and Logging

Extend `internal/metrics` with discovery-focused metrics. At minimum:

- provider startup attempts,
- provider startup failures,
- active provider count,
- identity overlaps,
- resolve hits, misses, and errors per provider.

Metric labels should identify provider name and provider kind where relevant.

Logging should cover:

- provider startup attempt,
- provider startup success,
- provider startup failure,
- resolve-time provider errors,
- overlap detections including winning provider and shadowed provider.

Logs should be informational and structured, not noisy per request when
providers return simple misses.

## Proxy Integration

`cmd/aegis/main.go` should pass the composite resolver into
`proxy.Dependencies.IdentityResolver`.

No changes are required to proxy policy semantics. The existing proxy behavior
already falls back to `identity.Unknown()` when no identity is resolved, and
this slice should preserve that behavior.

## Failure Handling

The runtime must tolerate partial discovery failure.

- A provider that fails to build, start, or sync is excluded from the active
  set.
- Remaining healthy providers continue serving traffic.
- Discovery-related failures are visible through logs and metrics.
- Startup fails only when discovery is configured and the active provider set is
  empty.

At request time:

- provider resolve errors must not fail the request directly,
- later providers are still queried,
- if no provider resolves the IP, proxy behavior falls back to unknown identity.

## Testing Strategy

### Composite resolver tests

Add unit tests in `internal/identity` covering:

- first-match precedence across multiple providers,
- overlap detection when multiple providers match the same IP,
- resolve-error tolerance and fallback to later providers,
- miss behavior when all providers return nil.

### Startup wiring tests

Add runtime tests around `cmd/aegis/main.go` covering:

- multiple providers are attempted in config order,
- a failed provider does not block a healthy provider,
- discovery-configured startup fails when zero providers become active,
- a successful startup injects a working identity resolver into the proxy path.

Tests should avoid live Kubernetes dependencies. Provider construction and
startup should be factored so fakes can be injected.

## Success Criteria

This slice is complete when:

- configured discovery providers are attempted at startup in config order,
- healthy providers are composed into a single runtime resolver,
- the proxy uses that resolver for request identity lookups,
- overlap, startup failure, and resolve-error behavior is observable through
  metrics and logs,
- partial provider startup failure is tolerated,
- startup fails only when discovery is configured and zero providers are active,
- repository tests and builds pass.
