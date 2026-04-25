# Aegis Kubernetes Identity Provider Design

**Date:** 2026-04-24
**Status:** Approved for implementation

## Goal

Implement a real Kubernetes-backed identity provider for Aegis that resolves pod
source IPs into the unified `identity.Identity` model.

This slice delivers the provider package and supporting config shape, but stops
before runtime wiring in `main` or proxy integration.

## Scope

### In scope

- Extend config to support `discovery.kubernetes`.
- Implement an informer-backed Kubernetes identity provider in
  `internal/identity`.
- Maintain an in-memory `podIP -> Identity` map based on pod add/update/delete
  events.
- Add tests for creation, deletion, IP change/reuse, namespace label injection,
  and unknown-IP behavior.
- Keep the provider lifecycle explicit and testable.

### Out of scope

- Wiring Kubernetes discovery into `main`.
- Injecting the provider into the proxy runtime.
- EC2 identity discovery.
- Composite multi-provider startup.
- Policy-engine changes.
- End-to-end cluster tests.

## Design Boundary

The provider is a package-level building block, not a runtime feature yet. It
must be usable by future startup wiring, but this slice should not change the
currently shipped runtime behavior.

That means the provider can be started in tests and expose `Resolve(net.IP)`,
but `cmd/aegis/main.go` and the proxy remain unchanged.

## Configuration Model

Add `discovery.kubernetes` to the config schema.

Each entry should contain:

- `name`
- `kubeconfig`
- `namespaces`
- `resyncPeriod`

### Validation rules

Config validation must enforce:

- each Kubernetes discovery entry has a non-empty `name`,
- `resyncPeriod` is positive when provided,
- `namespaces` entries are non-empty strings if specified.

`kubeconfig` may be empty to allow future in-cluster use.
An empty `namespaces` list means “all namespaces.”

## Identity Model

The provider should emit the unified `identity.Identity` shape:

- `Source: "kubernetes"`
- `Provider: <configured discovery name>`
- `Name: "<namespace>/<pod-name>"`
- `Labels`: pod labels plus injected namespace label

The namespace label must be injected as:

- `kubernetes.io/namespace: <namespace>`

This keeps policy selectors aligned with the config model already in use.

## Provider Architecture

The Kubernetes provider should own:

- a fakeable Kubernetes client dependency,
- informer startup and shutdown,
- an internal thread-safe IP map,
- translation from pod objects to `identity.Identity`.

### Lifecycle

Use an explicit lifecycle such as:

- constructor/build step,
- `Start(ctx)` to begin informer processing,
- `Resolve(ip)` for lookups.

Do not start background goroutines implicitly in the constructor.

### Mapping semantics

- If a pod has no `status.podIP`, ignore it.
- On add, create a mapping for the current pod IP.
- On update:
  - if the pod IP is unchanged, refresh the identity for that IP,
  - if the pod IP changed, remove the old mapping and create the new one.
- On delete, remove the mapping for the pod’s last known IP.

The provider must handle pod IP reuse correctly by treating the informer stream
as authoritative for current ownership.

## Resolver Semantics

`Resolve(ip)` should:

- return the matching `*Identity` for known pod IPs,
- return `nil` for unknown IPs,
- avoid panics on nil/empty input.

This provider does not define unknown-identity fallback itself; that remains the
responsibility of higher-level runtime code.

## Testing Strategy

### Config tests

Extend config tests to cover:

- valid Kubernetes discovery entries,
- missing discovery name,
- invalid empty namespace entries,
- invalid non-positive resync period.

### Provider tests

`internal/identity/kubernetes_test.go` must cover:

- pod creation becomes resolvable,
- pod deletion removes the mapping,
- pod IP change/reuse updates ownership correctly,
- namespace label injection works,
- pods without IPs are ignored,
- unknown IP resolution returns nil.

Tests should use fake Kubernetes clients and informer-driven event handling
rather than a live cluster.

## Success Criteria

This slice is complete when:

- config supports `discovery.kubernetes`,
- the Kubernetes provider can be started and resolve pod IPs correctly,
- informer-driven updates maintain correct map state,
- the provider emits the unified identity shape with namespace label injection,
- tests pass,
- the currently shipped runtime behavior remains unchanged.
