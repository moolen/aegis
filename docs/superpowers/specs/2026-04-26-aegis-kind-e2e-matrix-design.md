# Aegis Kind E2E Matrix Design

## Summary

Expand the current `kind_e2e` layer from one broad smoke test into a real
deployment-shaped matrix that runs on every PR. The suite will keep one shared
Kind cluster per CI job, build and load one Aegis image once, and execute
multiple focused tests with per-test namespace and Helm release isolation.

The goal is not to replace local subprocess e2e or cloud-provider integration
testing. The goal is to make the shipped Helm/Kubernetes shape credible and
regression-resistant in CI.

## Goals

- Cover the most important deployment-shaped proxy behaviors in Kind.
- Keep failures diagnosable by splitting scenarios into focused tests.
- Run the full Kind matrix on every PR in a dedicated CI job.
- Reuse one shared cluster and one built image per CI job to keep runtime
  acceptable.

## Non-Goals

- Real EKS/GKE/AKS live-cloud integration testing.
- Parallel multi-cluster or cross-cloud discovery testing.
- Replacing subprocess `e2e` tests that are already strong for local/runtime
  protocol behavior.

## Current Problem

Today the Kind layer is mostly one large test in
`e2e/kind_smoke_test.go`. It proves that Helm deploys and that some in-cluster
traffic and Kubernetes discovery behavior work, but it does not provide broad,
focused regression coverage. It is also not run in CI, so the most
production-shaped test layer is manual-only.

## Design

### Shared Cluster Model

The Kind matrix will use:

- one shared Kind cluster per CI job
- one shared image build and image load per CI job
- one namespace and one Helm release per test case

Tests will run sequentially against the shared cluster. This avoids cluster
setup explosion while still preserving meaningful isolation at the namespace and
release level.

### Test Layout

Refactor the current Kind code into:

- a shared suite helper for:
  - cluster lifecycle
  - image build/load
  - namespace/release naming
  - common upstream fixture deployment
  - common Helm install/upgrade helpers
  - common proxy/metrics/admin request helpers
- focused Kind tests split by scenario instead of one monolith

Expected file shape:

- `e2e/kind_suite_test.go`
- `e2e/kind_http_test.go`
- `e2e/kind_connect_test.go`
- `e2e/kind_mitm_test.go`
- `e2e/kind_identity_test.go`
- `e2e/kind_reload_test.go`
- `e2e/kind_limits_test.go`
- `e2e/kind_readiness_test.go`
- `e2e/kind_admin_test.go`

The old `kind_smoke_test.go` logic should be decomposed into helpers and
focused tests rather than preserved as the only large scenario.

### Scenario Matrix

#### 1. HTTP Policy Enforcement

Deploy the chart with a simple HTTP policy and assert:

- allowed path returns `200`
- denied path returns `403`

This proves plain HTTP policying in the actual Helm/Kubernetes shape.

#### 2. CONNECT Passthrough

Deploy an HTTPS upstream and a passthrough policy. Assert:

- allowed target succeeds through the proxy
- denied target is blocked

This proves deployment-shaped CONNECT passthrough policy behavior.

#### 3. MITM Inspection

Deploy an HTTPS upstream plus proxy CA secret and a MITM policy. Assert:

- allowed inner HTTP path succeeds
- denied inner HTTP path returns `403`

This proves deployment-shaped MITM interception and inner HTTP policy
enforcement.

#### 4. Kubernetes Discovery Identity

Deploy labeled allowed/denied pods and enable in-cluster Kubernetes discovery.
Assert that policies bound to the configured provider name, namespace, and pod
labels enforce correctly end to end.

This specifically validates the newer explicit policy subject binding model in
the real cluster shape.

#### 5. Reload

Change policy config in the deployed instance and exercise the shipped reload
path. Assert:

- traffic behavior changes as expected
- the instance remains healthy
- the deployment does not need to be recreated to apply a valid runtime-only
  config change

The test should use the product’s actual runtime reload semantics rather than a
fake in-process hook.

#### 6. Connection Limits

Deploy a low per-identity connection limit and assert:

- one concurrent request or tunnel succeeds
- the next is rejected

This should cover at least one deployment-shaped connection-limit path.

#### 7. Readiness Degradation

Deploy discovery config that cannot become active and assert:

- `/healthz` remains live
- `/readyz` reports not ready

This validates the intended distinction between liveness and readiness under
discovery failure.

#### 8. Admin Surface

When explicitly enabled, assert:

- admin endpoints behave as expected for the features Aegis operationally relies
  on
- especially the enforcement override path

Kind cannot easily prove true host-level localhost isolation of the admin
listener from outside the pod, so this test should focus on enabled runtime
behavior and expected in-pod access patterns.

#### 9. Listener / Config Invariants

Assert deployment-safety config failures where they matter in the shipped shape,
for example invalid mutually-exclusive or invalid listener settings that should
prevent a healthy deployment from coming up.

This should be done as deployment-facing negative tests, not just unit
validation duplication.

## CI Design

Add a dedicated `kind-e2e` job to `.github/workflows/ci.yml`:

- keep the existing `ci` job for fast unit/subprocess coverage
- add a new heavier job that:
  - checks out the repo
  - installs Go, Docker prerequisites, `kind`, `kubectl`, and `helm`
  - runs `go test -tags kind_e2e -timeout 45m ./e2e/...`

The Kind job should run on every PR and push, matching the requested coverage
bar.

## Isolation Rules

- tests run sequentially against one shared cluster
- each test uses a unique namespace
- each test uses a unique Helm release name
- helper cleanup must remove leftover releases/namespaces where needed
- the built image is reused for the whole job

This is the balance between real coverage and acceptable CI latency.

## Failure Diagnostics

Each focused test should fail with enough context to debug without rerunning the
whole matrix blindly. Helpers should capture and report:

- relevant `kubectl` command output
- deployment rollout failures
- proxy/metrics/admin request responses
- selected pod logs when a scenario fails

The main point is to keep the suite maintainable under PR pressure.

## Documentation

Update `e2e/README.md` so it reflects:

- subprocess `e2e` as the local/runtime protocol layer
- Kind `kind_e2e` as the deployment-shaped matrix
- the new scenario set
- the fact that Kind now runs in CI

## Risks

- CI runtime increases materially if the helper layer is not careful about
  cluster/image reuse.
- Overly monolithic helpers can recreate the same debugging problem the current
  Kind smoke test has. Helpers should be small and scenario-focused.
- Some listener-isolation guarantees are inherently harder to prove in Kind than
  in a real host/network environment. The suite should be explicit about what it
  proves and what still belongs to config/unit validation.

## Success Criteria

- The Kind layer is no longer a single broad smoke test.
- Every PR runs the expanded Kind matrix in CI.
- The matrix covers HTTP, passthrough, MITM, discovery identity, reload,
  connection limits, readiness degradation, admin behavior, and deployment-facing
  config invariants.
- Failures are attributable to focused scenarios instead of a giant catch-all
  test body.
