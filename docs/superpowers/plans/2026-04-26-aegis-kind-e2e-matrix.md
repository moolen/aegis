# Aegis Kind E2E Matrix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expand the Kind deployment-shaped e2e layer from one broad smoke test into a focused scenario matrix that runs on every PR with one shared Kind cluster and one shared built image per job.

**Architecture:** Keep the existing subprocess `e2e` suite intact, but refactor the `kind_e2e` layer around a shared suite harness that owns cluster/image lifecycle, namespace and release isolation, Helm deploy helpers, and failure diagnostics. Build focused scenario files on top of that harness for protocol, identity, operational, and negative deployment checks, then add a dedicated CI job that runs the full Kind matrix on every PR.

**Tech Stack:** Go, Kind, Helm, kubectl, Docker, existing Aegis e2e fixtures and Helm chart, GitHub Actions.

---

## File Map

### New files
- `e2e/kind_suite_test.go` — shared Kind cluster/image harness and deployment/test helpers.
- `e2e/kind_http_test.go` — plain HTTP allow/deny deployment tests.
- `e2e/kind_connect_test.go` — CONNECT passthrough deployment tests.
- `e2e/kind_mitm_test.go` — MITM deployment tests for inner HTTP allow/deny.
- `e2e/kind_identity_test.go` — in-cluster Kubernetes discovery and identity enforcement tests.
- `e2e/kind_reload_test.go` — deployment-shaped reload behavior tests.
- `e2e/kind_limits_test.go` — per-identity connection limit deployment tests.
- `e2e/kind_readiness_test.go` — readiness/liveness degradation tests.
- `e2e/kind_admin_test.go` — admin surface behavior tests when explicitly enabled.
- `deploy/helm/template_test.go` — focused Helm negative/invariant tests where static templating checks are the right fit.

### Modified files
- `e2e/kind_smoke_test.go` — remove or shrink the old monolithic test once scenarios are split out.
- `e2e/README.md` — document the new Kind matrix and CI behavior.
- `.github/workflows/ci.yml` — add the dedicated `kind-e2e` job on every PR/push.
- `Makefile` — ensure the existing Kind target remains aligned with the new matrix if changes are needed.

## Task 1: Build the shared Kind suite harness

**Files:**
- Create: `e2e/kind_suite_test.go`
- Modify: `e2e/kind_smoke_test.go`

- [ ] **Step 1: Inventory and isolate the reusable helper layer**

Read `e2e/kind_smoke_test.go` and identify the helpers that should move into the suite harness:

- cluster lifecycle (`createKindCluster`, cleanup, image build/load)
- namespace/release naming
- Helm install/upgrade helpers
- rollout and wait helpers
- `kubectl` exec/apply/log helpers
- proxy / metrics / admin request helpers
- failure-diagnostics helpers

Preserve behavior while separating helpers from the monolithic scenario body.

- [ ] **Step 2: Add the shared harness**

Create `e2e/kind_suite_test.go` with a package-level shared harness that:

- creates one Kind cluster for the test process
- builds and loads one Aegis image once
- exposes per-test methods like:
  - `newKindScenario(t *testing.T) kindScenario`
  - `scenario.Namespace() string`
  - `scenario.ReleaseName() string`
  - `scenario.InstallHelm(valuesFiles ...string)`
  - `scenario.UpgradeHelm(valuesFiles ...string)`
  - `scenario.WaitReady()`
  - `scenario.ProxyRequest(...)`
  - `scenario.MetricsRequest(...)`
  - `scenario.AdminRequest(...)`
  - `scenario.PodLogs(...)`
- captures useful logs/output on failure

Use `sync.Once` and process-wide setup for the cluster/image lifecycle so the suite remains shared-cluster, not per-test-cluster.

- [ ] **Step 3: Add focused harness tests where practical**

Where unit-style coverage is possible inside `e2e`, add small tests or assertions for:

- unique namespace / release generation
- idempotent shared cluster initialization
- failure diagnostics including pod log capture

Keep these small and targeted; the main correctness proof will still be the scenario tests.

- [ ] **Step 4: Decompose the old smoke test**

Trim `e2e/kind_smoke_test.go` so it no longer owns the whole deployment matrix. Either:

- delete it entirely once all behavior is covered elsewhere, or
- reduce it to the minimum wrapper or shared fixture logic still needed

Avoid keeping two divergent Kind paths alive.

- [ ] **Step 5: Verify the shared harness slice**

Run:

```bash
/usr/local/go/bin/go test -tags kind_e2e ./e2e/... -run 'TestKind' -count=1
```

Expected: the shared harness and any migrated tests compile and run cleanly.

## Task 2: Add focused protocol and identity Kind scenarios

**Files:**
- Create: `e2e/kind_http_test.go`
- Create: `e2e/kind_connect_test.go`
- Create: `e2e/kind_mitm_test.go`
- Create: `e2e/kind_identity_test.go`

- [ ] **Step 1: Add HTTP allow/deny deployment coverage**

In `e2e/kind_http_test.go`, add a test like:

```go
func TestKindHTTPPolicyEnforcement(t *testing.T)
```

It should:

- deploy a simple HTTP policy via Helm values
- verify `/allowed -> 200`
- verify `/denied -> 403`
- fail with response bodies and relevant pod logs if behavior regresses

- [ ] **Step 2: Add CONNECT passthrough deployment coverage**

In `e2e/kind_connect_test.go`, add a test like:

```go
func TestKindConnectPassthroughPolicyEnforcement(t *testing.T)
```

It should:

- deploy an HTTPS upstream
- configure passthrough policy
- verify allowed target succeeds through the proxy
- verify denied target is blocked

- [ ] **Step 3: Add MITM deployment coverage**

In `e2e/kind_mitm_test.go`, add a test like:

```go
func TestKindMITMInnerHTTPPolicyEnforcement(t *testing.T)
```

It should:

- deploy the proxy CA secret
- configure MITM policy
- verify an allowed inner HTTP path succeeds
- verify a denied inner path returns `403`

- [ ] **Step 4: Add Kubernetes discovery identity coverage**

In `e2e/kind_identity_test.go`, add a test like:

```go
func TestKindKubernetesDiscoveryIdentityEnforcement(t *testing.T)
```

It should:

- enable in-cluster Kubernetes discovery
- create labeled allowed/denied client pods
- bind policies to the configured discovery provider name plus namespace + labels
- prove identical labels in the wrong subject scope do not match

- [ ] **Step 5: Verify the protocol/identity slice**

Run:

```bash
/usr/local/go/bin/go test -tags kind_e2e ./e2e/... -run 'TestKind(HTTP|Connect|MITM|KubernetesDiscovery)' -count=1
```

Expected: the protocol and identity scenario set passes against the shared cluster harness.

## Task 3: Add operational and negative deployment scenarios

**Files:**
- Create: `e2e/kind_reload_test.go`
- Create: `e2e/kind_limits_test.go`
- Create: `e2e/kind_readiness_test.go`
- Create: `e2e/kind_admin_test.go`
- Create or modify: `deploy/helm/template_test.go`

- [ ] **Step 1: Add reload behavior coverage**

In `e2e/kind_reload_test.go`, add:

```go
func TestKindReloadAppliesRuntimeConfigChanges(t *testing.T)
```

It should:

- deploy an initial allowed policy
- change the runtime config through the shipped reload path
- prove traffic behavior flips without breaking health

- [ ] **Step 2: Add connection limit coverage**

In `e2e/kind_limits_test.go`, add:

```go
func TestKindConnectionLimits(t *testing.T)
```

It should:

- configure a low per-identity connection limit
- verify one request/tunnel succeeds while the next concurrent one is rejected

- [ ] **Step 3: Add readiness degradation coverage**

In `e2e/kind_readiness_test.go`, add:

```go
func TestKindReadinessDegradesWhenDiscoveryIsInactive(t *testing.T)
```

It should:

- deploy a discovery config that cannot become active
- assert `/healthz` remains live
- assert `/readyz` reports not ready

- [ ] **Step 4: Add admin surface deployment coverage**

In `e2e/kind_admin_test.go`, add:

```go
func TestKindAdminEnforcementOverride(t *testing.T)
```

It should:

- explicitly enable admin in the deployment
- access it through the expected in-pod/local-only pattern
- verify enforcement override behavior you operationally rely on

- [ ] **Step 5: Add deployment-facing invariant checks**

Where static or startup-failure checks are the right fit, add deployment-facing coverage for invalid listener/config invariants such as:

- invalid listener collisions
- admin enablement without valid localhost listen
- other Helm-rendered startup-fatal combinations that matter in shipped deployments

Use `deploy/helm/template_test.go` or negative deployment tests as appropriate; do not duplicate unit validation mechanically.

- [ ] **Step 6: Verify the operational slice**

Run:

```bash
/usr/local/go/bin/go test -tags kind_e2e ./e2e/... -run 'TestKind(Reload|ConnectionLimits|Readiness|Admin)' -count=1
/usr/local/go test ./deploy/helm/... -count=1
```

Expected: operational and negative deployment tests pass cleanly.

## Task 4: Run the full matrix on every PR and document it

**Files:**
- Modify: `.github/workflows/ci.yml`
- Modify: `e2e/README.md`
- Modify: `Makefile` (only if needed)

- [ ] **Step 1: Add the dedicated CI job**

Update `.github/workflows/ci.yml` to add a `kind-e2e` job that:

- runs on every PR and push
- installs `kind`, `kubectl`, and `helm`
- reuses the repo’s Go/Docker setup
- runs:

```bash
/usr/local/go/bin/go test -tags kind_e2e -timeout 45m ./e2e/...
```

Keep the existing fast `ci` job intact.

- [ ] **Step 2: Update documentation**

Update `e2e/README.md` to describe:

- subprocess `e2e` as the local/runtime protocol layer
- `kind_e2e` as the deployment-shaped matrix
- the new focused scenario set
- the fact that the full Kind matrix now runs in CI on every PR

If `Makefile` needs target wording or comments updated to reflect the matrix, update that too.

- [ ] **Step 3: Verify the CI/docs slice**

Run:

```bash
helm template aegis ./deploy/helm
rg -n "kind-e2e|kind_e2e|every PR|deployment-shaped matrix" .github/workflows/ci.yml e2e/README.md Makefile
```

Expected: CI and docs clearly reflect the new Kind matrix.

## Task 5: Full verification and cleanup

**Files:**
- Whole repo as touched by Tasks 1-4

- [ ] **Step 1: Run the full verification matrix**

Run:

```bash
/usr/local/go/bin/go test ./...
/usr/local/go/bin/go test -tags e2e ./e2e/...
/usr/local/go/bin/go test -tags kind_e2e -timeout 45m ./e2e/...
helm template aegis ./deploy/helm
docker build -t aegis:dev .
```

Expected: all tests and deployment checks pass.

- [ ] **Step 2: Review for duplication and leftover monolith logic**

Make sure:

- old `kind_smoke_test.go` monolith logic is removed or minimized
- the harness owns cluster/image lifecycle in one place
- scenario files stay focused and readable
- each failure path emits actionable diagnostics

- [ ] **Step 3: Commit the completed Kind matrix**

```bash
git add e2e .github/workflows/ci.yml deploy/helm Makefile docs/superpowers/plans/2026-04-26-aegis-kind-e2e-matrix.md
git commit -m "test: expand kind e2e matrix"
```

## Notes for Subagent Execution

- **Critical path:** Task 1 must complete before the focused Kind scenario tasks.
- **Safe parallelism after Task 1:**
  - one worker can own `e2e/kind_http_test.go`, `e2e/kind_connect_test.go`, `e2e/kind_mitm_test.go`, `e2e/kind_identity_test.go`
  - a second worker can own `e2e/kind_reload_test.go`, `e2e/kind_limits_test.go`, `e2e/kind_readiness_test.go`, `e2e/kind_admin_test.go`, and any negative deployment tests
  - a third worker can own `.github/workflows/ci.yml`, `e2e/README.md`, and any Makefile wording updates once the new file layout is stable
- **Review discipline:** review each worker slice before starting the next dependent slice so the shared harness stays coherent.
