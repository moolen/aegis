# Aegis Proxy Request Flow Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Split `internal/proxy/server.go` into deeper internal modules centered on a normalized request-flow decision while preserving current proxy behavior.

**Architecture:** Keep one public `internal/proxy` package and preserve `NewServer(deps)` as the only public construction seam. Introduce a private request-flow result that centralizes identity, policy, audit, unknown-identity, and connection-limit behavior, then move HTTP, CONNECT, MITM, and observability code behind focused files that consume that result.

**Tech Stack:** Go, `net/http`, `crypto/tls`, Prometheus, existing Aegis proxy/policy/identity packages

---

### Task 1: Introduce normalized request-flow evaluation

**Files:**
- Create: `internal/proxy/request_flow.go`
- Modify: `internal/proxy/server.go`
- Modify: `internal/proxy/server_test.go`

- [ ] **Step 1: Write failing request-flow tests**

Add focused tests covering shared policy behavior that should move behind the new seam.

```go
func TestEvaluateRequestFlowDeniesUnknownIdentityWhenConfigured(t *testing.T) {}
func TestEvaluateRequestFlowReturnsAuditWouldDenyForHTTP(t *testing.T) {}
func TestEvaluateRequestFlowResolvesConnectModeForMITM(t *testing.T) {}
func TestEvaluateRequestFlowRejectsConnectionLimit(t *testing.T) {}
```

- [ ] **Step 2: Run the focused proxy tests and verify they fail**

Run: `/usr/local/go/bin/go test ./internal/proxy -run 'TestEvaluateRequestFlow'`
Expected: FAIL with missing request-flow symbols.

- [ ] **Step 3: Implement the private flow result and evaluator**

Create a private evaluator that centralizes target parsing, identity resolution, policy evaluation, audit/shadow handling, unknown-identity handling, and connection-limit acquisition.

```go
type requestFlow struct {
	protocol string
	host     string
	port     int
	identity *identity.Identity
	decision *policy.Decision
	audit    auditOutcome
	action   string
	reason   string
	mode     string
	release  func()
}
```

- [ ] **Step 4: Make `handleHTTP`, `handleConnect`, and MITM request handling consume the new flow result**

Keep behavior stable; only replace duplicated policy/audit decision-making with the new evaluator.

- [ ] **Step 5: Run proxy tests**

Run: `/usr/local/go/bin/go test ./internal/proxy`
Expected: PASS, or a narrowed set of transport-specific failures to handle in Task 2.

### Task 2: Split transport and observability modules

**Files:**
- Create: `internal/proxy/http_flow.go`
- Create: `internal/proxy/connect_flow.go`
- Create: `internal/proxy/mitm_flow.go`
- Create: `internal/proxy/observability.go`
- Modify: `internal/proxy/server.go`
- Modify: `internal/proxy/server_test.go`
- Modify: `internal/proxy/tls_mitm_test.go`
- Modify: `internal/proxy/http2_mitm_test.go`

- [ ] **Step 1: Write or move tests that pin the new internal seams**

Keep end-to-end proxy tests, but add or move focused tests for transport-only behavior where needed.

```go
func TestHTTPFlowTranslatesDNSFailure(t *testing.T) {}
func TestConnectFlowBlocksSNIMismatch(t *testing.T) {}
func TestMITMFlowForwardsAllowedRequest(t *testing.T) {}
```

- [ ] **Step 2: Run the targeted proxy tests and verify red state where new files are expected**

Run: `/usr/local/go/bin/go test ./internal/proxy -run 'TestHTTPFlow|TestConnectFlow|TestMITM'`
Expected: FAIL on missing helpers or moved symbols.

- [ ] **Step 3: Move plain HTTP forwarding into `http_flow.go`**

The HTTP transport module should assume the request-flow decision has already allowed the request.

- [ ] **Step 4: Move CONNECT tunnel behavior into `connect_flow.go`**

The CONNECT transport module should consume the normalized mode instead of recomputing policy/audit logic.

- [ ] **Step 5: Move MITM request/session behavior into `mitm_flow.go` and logging/metrics helpers into `observability.go`**

Keep `server.go` thin and dispatch-oriented.

- [ ] **Step 6: Run the full proxy package tests**

Run: `/usr/local/go/bin/go test ./internal/proxy`
Expected: PASS.

### Task 3: Verify preservation and clean up refactor edges

**Files:**
- Modify: `internal/proxy/server.go`
- Modify: `internal/proxy/request_flow.go`
- Modify: `internal/proxy/http_flow.go`
- Modify: `internal/proxy/connect_flow.go`
- Modify: `internal/proxy/mitm_flow.go`
- Modify: `internal/proxy/observability.go`
- Modify: `internal/proxy/server_test.go`

- [ ] **Step 1: Run the broader regression net**

Run: `/usr/local/go/bin/go test ./internal/proxy ./internal/runtime ./cmd/aegis`
Expected: PASS.

- [ ] **Step 2: Run the full repository suite**

Run: `/usr/local/go/bin/go test ./...`
Expected: PASS.

- [ ] **Step 3: Inspect the resulting shape for shallow leftovers**

Check that:

- `server.go` is mostly constructor plus dispatch,
- policy/audit logic is centralized,
- HTTP/CONNECT/MITM modules do not reconstruct request-flow behavior,
- observability helpers no longer dominate transport modules.

- [ ] **Step 4: Commit the refactor**

Run:

```bash
git add internal/proxy docs/superpowers/plans/2026-05-08-aegis-proxy-request-flow.md docs/superpowers/specs/2026-05-08-aegis-proxy-request-flow-design.md
git commit -m "refactor: split proxy request flow"
```
