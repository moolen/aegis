# Aegis Pprof Profiling Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an opt-in localhost-only `pprof` listener to Aegis, document how to use it, and capture one real MITM-knee profile to guide the follow-on HTTP/2 work.

**Architecture:** The profiling surface will be a dedicated HTTP server, separate from proxy, metrics, and admin. It will be disabled by default, validated as localhost-only, wired into normal startup/shutdown, and documented for both direct runtime use and perf-harness investigations.

**Tech Stack:** Go, `net/http/pprof`, existing Aegis config/runtime wiring, Go tests, existing perf harness and docs.

---

## File Map

### New files
- `internal/metrics/pprof_server.go` — dedicated localhost-only `pprof` mux construction.
- `internal/metrics/pprof_server_test.go` — focused tests for `pprof` endpoint exposure.

### Modified files
- `internal/config/config.go` — add `pprof` config types, defaults, validation, and listener-collision checks.
- `internal/config/config_test.go` — validate localhost-only binds, required listen address, and listener conflicts.
- `cmd/aegis/main.go` — build and run the optional `pprof` server alongside the existing listeners.
- `cmd/aegis/main_test.go` — startup/shutdown coverage for the optional `pprof` listener.
- `README.md` — operator-facing config overview for `pprof`.
- `aegis.example.yaml` — disabled-by-default example block.
- `perf/README.md` — how to capture a CPU/heap/goroutine profile during a perf run.

## Task 1: Add config and validation for the profiling listener

**Files:**
- Modify: `internal/config/config.go`
- Test: `internal/config/config_test.go`

- [ ] **Step 1: Write the failing config tests**

Add tests covering:

```go
func TestValidateRejectsEnabledPprofWithoutListen(t *testing.T)
func TestValidateRejectsNonLocalhostPprofListen(t *testing.T)
func TestValidateRejectsPprofListenerCollision(t *testing.T)
func TestValidateAcceptsLocalhostPprofListen(t *testing.T)
```

Use config values like:

```go
cfg.Pprof.Enabled = true
cfg.Pprof.Listen = ""
```

and:

```go
cfg.Pprof.Enabled = true
cfg.Pprof.Listen = "0.0.0.0:6060"
```

and:

```go
cfg.Pprof.Enabled = true
cfg.Pprof.Listen = "127.0.0.1:6060"
cfg.Metrics.Listen = "127.0.0.1:6060"
```

- [ ] **Step 2: Run the config tests to verify they fail**

Run: `/usr/local/go/bin/go test ./internal/config -run 'TestValidate(RejectsEnabledPprofWithoutListen|RejectsNonLocalhostPprofListen|RejectsPprofListenerCollision|AcceptsLocalhostPprofListen)' -count=1`

Expected: FAIL because `pprof` config and validation do not exist yet.

- [ ] **Step 3: Implement minimal config support**

In `internal/config/config.go`:

- add:

```go
type PprofConfig struct {
    Enabled bool   `yaml:"enabled"`
    Listen  string `yaml:"listen"`
}
```

- add `Pprof PprofConfig \`yaml:"pprof"\`` to the root config
- keep default zero-value disabled
- in validation:
  - require `Listen` when enabled
  - validate localhost-only host values:
    - `127.0.0.1`
    - `::1`
    - `localhost`
  - reject collisions with proxy / metrics / admin listeners

- [ ] **Step 4: Run the config tests to verify they pass**

Run: `/usr/local/go/bin/go test ./internal/config -run 'TestValidate(RejectsEnabledPprofWithoutListen|RejectsNonLocalhostPprofListen|RejectsPprofListenerCollision|AcceptsLocalhostPprofListen)' -count=1`

Expected: PASS

- [ ] **Step 5: Commit the config slice**

```bash
git add internal/config/config.go internal/config/config_test.go
git commit -m "feat: add pprof listener config"
```

## Task 2: Add the dedicated pprof server

**Files:**
- Create: `internal/metrics/pprof_server.go`
- Test: `internal/metrics/pprof_server_test.go`

- [ ] **Step 1: Write the failing server tests**

Create tests like:

```go
func TestNewPprofServerExposesIndex(t *testing.T)
func TestNewPprofServerExposesHeapProfile(t *testing.T)
```

The tests should create the handler and make requests to:

- `/debug/pprof/`
- `/debug/pprof/heap`

and assert `200 OK`.

- [ ] **Step 2: Run the pprof server tests to verify they fail**

Run: `/usr/local/go/bin/go test ./internal/metrics -run 'TestNewPprofServer(ExposesIndex|ExposesHeapProfile)' -count=1`

Expected: FAIL because the server constructor does not exist yet.

- [ ] **Step 3: Implement the dedicated pprof server**

Create `internal/metrics/pprof_server.go` with:

```go
package metrics

import (
    "net/http"
    httppprof "net/http/pprof"
)

func NewPprofServer(addr string) *Server {
    mux := http.NewServeMux()
    mux.HandleFunc("/debug/pprof/", httppprof.Index)
    mux.HandleFunc("/debug/pprof/cmdline", httppprof.Cmdline)
    mux.HandleFunc("/debug/pprof/profile", httppprof.Profile)
    mux.HandleFunc("/debug/pprof/symbol", httppprof.Symbol)
    mux.HandleFunc("/debug/pprof/trace", httppprof.Trace)
    mux.HandleFunc("/debug/pprof/allocs", httppprof.Handler("allocs").ServeHTTP)
    mux.HandleFunc("/debug/pprof/block", httppprof.Handler("block").ServeHTTP)
    mux.HandleFunc("/debug/pprof/goroutine", httppprof.Handler("goroutine").ServeHTTP)
    mux.HandleFunc("/debug/pprof/heap", httppprof.Handler("heap").ServeHTTP)
    mux.HandleFunc("/debug/pprof/mutex", httppprof.Handler("mutex").ServeHTTP)
    mux.HandleFunc("/debug/pprof/threadcreate", httppprof.Handler("threadcreate").ServeHTTP)
    return &Server{addr: addr, handler: mux}
}
```

- [ ] **Step 4: Run the metrics tests to verify they pass**

Run: `/usr/local/go/bin/go test ./internal/metrics -run 'TestNewPprofServer(ExposesIndex|ExposesHeapProfile)' -count=1`

Expected: PASS

- [ ] **Step 5: Commit the pprof server**

```bash
git add internal/metrics/pprof_server.go internal/metrics/pprof_server_test.go
git commit -m "feat: add pprof server"
```

## Task 3: Wire the optional profiling server into startup and shutdown

**Files:**
- Modify: `cmd/aegis/main.go`
- Test: `cmd/aegis/main_test.go`

- [ ] **Step 1: Write the failing runtime tests**

Add tests covering:

```go
func TestBuildServersIncludesPprofWhenEnabled(t *testing.T)
func TestBuildServersOmitsPprofWhenDisabled(t *testing.T)
```

Use a config with:

```go
cfg.Pprof.Enabled = true
cfg.Pprof.Listen = "127.0.0.1:6060"
```

and assert the returned pprof server is non-`nil`.

- [ ] **Step 2: Run the runtime tests to verify they fail**

Run: `/usr/local/go/bin/go test ./cmd/aegis -run 'TestBuildServers(IncludesPprofWhenEnabled|OmitsPprofWhenDisabled)' -count=1`

Expected: FAIL because `buildServers` and `runServe` do not handle `pprof`.

- [ ] **Step 3: Implement minimal runtime wiring**

In `cmd/aegis/main.go`:

- extend server creation to include a fourth optional `pprof` server
- create it with `appmetrics.NewPprofServer(cfg.Pprof.Listen)` when enabled
- start it in its own goroutine
- log it like the other listeners
- include it in shutdown

Keep the listener separate from proxy / metrics / admin.

- [ ] **Step 4: Run the runtime tests to verify they pass**

Run: `/usr/local/go/bin/go test ./cmd/aegis -run 'TestBuildServers(IncludesPprofWhenEnabled|OmitsPprofWhenDisabled)' -count=1`

Expected: PASS

- [ ] **Step 5: Commit the runtime wiring**

```bash
git add cmd/aegis/main.go cmd/aegis/main_test.go
git commit -m "feat: wire optional pprof listener"
```

## Task 4: Document operator usage and perf capture flow

**Files:**
- Modify: `README.md`
- Modify: `aegis.example.yaml`
- Modify: `perf/README.md`

- [ ] **Step 1: Add the example config and doc text**

Update `aegis.example.yaml`:

```yaml
pprof:
  enabled: false
  listen: "127.0.0.1:6060"
```

Update `README.md` with a short profiling section:

```md
## Profiling

`pprof` is disabled by default and can be enabled on a localhost-only listener:

```yaml
pprof:
  enabled: true
  listen: "127.0.0.1:6060"
```
```

Update `perf/README.md` with example capture commands:

```bash
go tool pprof http://127.0.0.1:6060/debug/pprof/profile?seconds=30
go tool pprof http://127.0.0.1:6060/debug/pprof/heap
curl -fsS http://127.0.0.1:6060/debug/pprof/goroutine?debug=1
```

- [ ] **Step 2: Verify the docs contain the profiling guidance**

Run: `rg -n "pprof|debug/pprof|127.0.0.1:6060" README.md aegis.example.yaml perf/README.md`

Expected: matches in all three files.

- [ ] **Step 3: Commit the docs**

```bash
git add README.md aegis.example.yaml perf/README.md
git commit -m "docs: add pprof profiling guidance"
```

## Task 5: Run full verification and capture one real profile

**Files:**
- Modify: `perf/README.md` (only if the actual capture flow needs a small correction)

- [ ] **Step 1: Run the relevant automated verification**

Run:

```bash
/usr/local/go/bin/go test ./...
helm template aegis ./deploy/helm >/tmp/aegis-helm-template.out
```

Expected: all Go tests pass and Helm renders successfully.

- [ ] **Step 2: Start a real profiling run against the MITM knee**

Use a localhost-enabled profiling config and a real perf scenario, for example:

```bash
IMAGE_REF="aegis:perf-kind-mitm-cap-<tag>" KEEP_CLUSTER=1 VUS=200 DURATION=15s SLEEP_SECONDS=0 ./perf/scripts/run-kind-connect-mitm.sh
```

Capture:

```bash
go tool pprof -proto http://127.0.0.1:6060/debug/pprof/profile?seconds=15 > /tmp/aegis-mitm-cpu.pb.gz
go tool pprof -proto http://127.0.0.1:6060/debug/pprof/heap > /tmp/aegis-mitm-heap.pb.gz
curl -fsS http://127.0.0.1:6060/debug/pprof/goroutine?debug=1 > /tmp/aegis-mitm-goroutines.txt
```

Expected: all profile artifacts are created successfully.

- [ ] **Step 3: Record the profiling outcome**

If the exact capture steps needed adjustment, update `perf/README.md` with the
working commands and short notes about where the pprof listener lives during the
perf run.

- [ ] **Step 4: Commit the verification/doc correction if needed**

```bash
git add perf/README.md
git commit -m "docs: refine pprof capture workflow"
```

## Self-Review

- Spec coverage:
  - config shape and validation: Task 1
  - dedicated runtime surface: Tasks 2 and 3
  - docs and operator flow: Task 4
  - one real MITM-knee capture: Task 5
- Placeholder scan:
  - no `TODO`, `TBD`, or vague “implement later” markers remain
  - every code-changing task includes concrete files and commands
- Type consistency:
  - `PprofConfig`, `NewPprofServer`, and the startup wiring names are used consistently throughout the plan

