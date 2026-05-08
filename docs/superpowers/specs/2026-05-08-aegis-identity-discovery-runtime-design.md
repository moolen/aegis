# Aegis Identity Discovery Runtime Design

## Summary

The identity discovery providers themselves are reasonably modular today, but the runtime assembly still lives in `internal/runtime/discovery.go`.

`internal/runtime` currently owns:

- Kubernetes provider construction
- EC2 provider construction
- provider startup sequencing
- startup timeout policy
- provider failure handling
- active-provider filtering
- composite resolver assembly

That makes the discovery adapter seam shallower than it should be. The runtime module still knows too much about provider-specific startup behavior and resolver composition.

This refactor deepens the identity discovery module by introducing a real discovery runtime in `internal/identity` that owns provider lifecycle and composite resolver assembly behind a small interface.

## Problem

Today the architecture is split awkwardly:

- `internal/identity/runtime.go` knows how to build provider handles.
- `internal/runtime/discovery.go` knows how to turn those handles into a running discovery system.

That split leaks important adapter semantics out of the identity module:

- default provider startup timeouts
- what happens when a provider fails to build
- what happens when a provider fails to start
- how providers are ordered in the composite resolver
- when discovery configuration counts as “configured but no providers active”

As a result, changing discovery startup behavior requires edits in runtime assembly rather than in one identity-runtime module.

## Goal

Move identity discovery runtime semantics into `internal/identity`.

`internal/runtime` should consume one high-level identity discovery runtime seam that:

- builds configured providers
- starts them with the configured/default timeout policy
- filters failed providers
- assembles the composite resolver
- reports “configured but no active providers” consistently

The runtime module should stop knowing the details of provider startup orchestration.

## Non-Goals

- Changing the Kubernetes or EC2 provider implementations themselves
- Changing composite resolver precedence rules
- Changing readiness or dump behavior semantics
- Merging identity discovery and policy discovery into one runtime

## Proposed Design

### New Identity Discovery Runtime

Add a runtime assembly module under `internal/identity`, for example:

- `internal/identity/discovery_runtime.go`

This module should own:

- provider build orchestration from discovery config
- provider start orchestration
- startup timeout application
- active provider collection
- composite resolver construction

Representative interface:

```go
type DiscoveryRuntime struct {
    ...
}

func NewDiscoveryRuntime(cfg config.DiscoveryConfig, logger *slog.Logger, metrics *appmetrics.Metrics) *DiscoveryRuntime

func (r *DiscoveryRuntime) Start(ctx context.Context) (*CompositeResolver, error)
```

The exact shape can differ, but the important rule is that `internal/runtime` should no longer manually iterate over provider configs and start them itself.

### Runtime Ownership After Refactor

After this change:

- `internal/identity` owns:
  - provider construction defaults
  - provider startup timeout policy
  - provider start error handling
  - active-provider collection
  - composite resolver assembly

- `internal/runtime` owns:
  - deciding whether to build identity discovery at all
  - storing the resulting resolver in the runtime generation

## Module Changes

### `internal/identity`

Add a new discovery runtime module that:

1. Builds provider handles from Kubernetes and EC2 config.
2. Starts each provider with the runtime startup timeout.
3. Logs and skips providers that fail to build or start.
4. Returns:
   - `nil, nil` when discovery is not configured
   - a composite resolver when at least one provider is active
   - an error when discovery is configured but no providers become active

Keep the existing exported provider constructors:

- `NewKubernetesRuntimeProvider`
- `NewEC2RuntimeProvider`

They remain useful as lower-level building blocks and keep the package layered.

### `internal/runtime`

Simplify `buildIdentityResolver` so it delegates to the new identity discovery runtime instead of orchestrating providers directly.

`internal/runtime/discovery.go` should stop owning:

- provider startup loops
- provider timeout handling
- active provider slice assembly

## Error Handling

The identity discovery runtime should centralize the current policy:

- provider build failure:
  - log warning
  - continue
- provider start failure:
  - log warning
  - continue
- no configured providers:
  - return `nil, nil`
- discovery configured but none active:
  - return an error

That behavior should stay the same unless tests or spec explicitly change it.

## Testing Strategy

### New Identity Runtime Tests

Add focused tests in `internal/identity` for:

- no discovery configured returns nil resolver
- successful Kubernetes startup contributes one active provider
- successful EC2 startup contributes one active provider
- provider build failure is skipped
- provider start failure is skipped
- mixed providers preserve ordering
- configured discovery with zero active providers returns an error

### Runtime Regression Coverage

Keep runtime tests green for:

- generation builds with identity discovery
- startup failure behavior remains stable
- identity dump / readiness still work through the composite resolver

The goal is to move provider-runtime semantics down into `internal/identity`, not to weaken runtime coverage.

## Rollout Plan

1. Introduce `internal/identity` discovery runtime and tests.
2. Move provider orchestration out of `internal/runtime/discovery.go`.
3. Update runtime build path to consume the new seam.
4. Remove dead runtime-specific discovery assembly helpers.
5. Run full regression coverage.

## Expected Benefits

- **Better locality**: discovery startup behavior changes land in `internal/identity`
- **Cleaner runtime assembly**: `internal/runtime` stops managing provider lifecycle details
- **Deeper discovery module**: callers ask for a running discovery resolver, not a bag of provider handles
- **Stronger tests**: adapter-runtime behavior gets direct unit coverage in the identity package

## Acceptance Criteria

- `internal/runtime` no longer loops over Kubernetes/EC2 discovery providers directly.
- identity discovery startup semantics live in `internal/identity`.
- identity discovery runtime has focused unit coverage.
- existing runtime behavior remains green under `go test ./...`.
