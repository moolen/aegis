# Aegis Runtime Assembly Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extract process startup, reload, server lifecycle, and generation orchestration into `internal/runtime` so `cmd/aegis` is reduced to CLI parsing and runtime invocation.

**Architecture:** Introduce a deep `internal/runtime` seam that owns config loading, generation assembly, remote policy discovery lifecycle, listener/server construction, and the control loop. Preserve existing behavior by moving current runtime logic mostly intact first, then shrinking `cmd/aegis` to a thin shell over the new package.

**Tech Stack:** Go, `net/http`, `slog`, Prometheus, existing Aegis internal packages

---

### Task 1: Create `internal/runtime` and migrate runtime lifecycle ownership

**Files:**
- Create: `internal/runtime/runtime.go`
- Create: `internal/runtime/build.go`
- Create: `internal/runtime/discovery.go`
- Create: `internal/runtime/servers.go`
- Create: `internal/runtime/runtime_test.go`
- Modify: `cmd/aegis/main.go`
- Modify: `cmd/aegis/reload.go`
- Modify: `cmd/aegis/main_test.go`

- [ ] **Step 1: Write failing package-level runtime tests**

Add tests in `internal/runtime/runtime_test.go` by moving the lifecycle-oriented cases that currently pin behavior in `cmd/aegis/main_test.go`, including reload success/failure and remote policy snapshot application. Keep the test names and assertions stable so the package move is behavior-preserving.

```go
func TestManagerReloadSwapsHandlerAndCountsSuccess(t *testing.T) { /* moved from cmd/aegis */ }
func TestManagerReloadFailureKeepsCurrentHandlerAndCountsError(t *testing.T) { /* moved from cmd/aegis */ }
func TestManagerAppliesRemotePolicySnapshotUpdate(t *testing.T) { /* moved from cmd/aegis */ }
func TestManagerKeepsLastGoodRemotePolicySnapshotOnFailure(t *testing.T) { /* moved from cmd/aegis */ }
```

- [ ] **Step 2: Run the new runtime tests and confirm they fail for missing symbols**

Run: `go test ./internal/runtime -run 'TestManager|TestBuild|TestRun'`
Expected: FAIL with missing package, missing types, or missing functions such as `NewManager`, `Run`, or runtime builder helpers.

- [ ] **Step 3: Move runtime lifecycle code into `internal/runtime`**

Create runtime-owned files that absorb the current behavior from `cmd/aegis/main.go` and `cmd/aegis/reload.go`.

```go
// internal/runtime/runtime.go
type Options struct {
	ConfigPath string
	Logger     *slog.Logger
}

func Run(ctx context.Context, opts Options) error { /* load config, build app, serve, reload, shutdown */ }
```

```go
// internal/runtime/runtime.go
type reloadableProxyHandler struct {
	current atomic.Value
}

type Manager struct {
	// moved runtime manager fields from cmd/aegis/reload.go
}
```

```go
// internal/runtime/build.go
func buildProxyDependencies(ctx context.Context, cfg config.Config, logger *slog.Logger, m *appmetrics.Metrics, drain *proxy.DrainTracker, limiter *proxy.ConnectionLimiter, enforcement *proxy.EnforcementOverrideController) (proxy.Dependencies, error) {
	// moved from cmd/aegis/main.go
}
```

```go
// internal/runtime/servers.go
func buildServers(ctx context.Context, cfg config.Config, logger *slog.Logger) (*http.Server, *http.Server, *http.Server, *http.Server, *appmetrics.Metrics, error) {
	// moved from cmd/aegis/main.go
}
```

- [ ] **Step 4: Keep `cmd/aegis` compiling with temporary wrappers if needed**

Leave thin forwarding wrappers in `cmd/aegis` only if required to keep unrelated CLI tests stable during the move.

```go
func runServe(args []string) int {
	// thin wrapper around runtime.Run
}
```

- [ ] **Step 5: Run the migrated runtime tests and package tests**

Run: `go test ./internal/runtime ./cmd/aegis`
Expected: PASS for moved runtime tests, or a short list of remaining compile/test failures only in CLI-adjacent areas that Task 2 will fix.

### Task 2: Thin `cmd/aegis` to CLI-only ownership

**Files:**
- Modify: `cmd/aegis/main.go`
- Modify: `cmd/aegis/commands.go`
- Modify: `cmd/aegis/main_test.go`
- Test: `cmd/aegis/main_test.go`

- [ ] **Step 1: Write failing CLI-focused tests for runtime invocation**

Add or update tests so `cmd/aegis` is only responsible for flag parsing, exit codes, and invoking the runtime entrypoint. Use an injected runtime function variable to make the contract explicit.

```go
func TestRunServeInvokesRuntimeRunWithConfigPath(t *testing.T) { /* capture runtime.Options */ }
func TestRunServeReturnsOneWhenRuntimeFails(t *testing.T) { /* runtime returns error */ }
```

- [ ] **Step 2: Run the focused CLI tests and verify they fail**

Run: `go test ./cmd/aegis -run 'TestRunServe'`
Expected: FAIL because `runServe` still owns orchestration directly or does not expose an injectable runtime seam yet.

- [ ] **Step 3: Reduce `cmd/aegis/main.go` to a thin shell**

Inject the runtime entrypoint and remove lifecycle code from the CLI package.

```go
var runRuntime = runtime.Run

func runServe(args []string) int {
	fs := newFlagSet("aegis")
	configPath := fs.String("config", "aegis.example.yaml", "Path to the Aegis configuration file.")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 2
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := runRuntime(ctx, runtime.Options{ConfigPath: *configPath, Logger: logger}); err != nil {
		logger.Error("aegis exited", "error", err)
		return 1
	}
	return 0
}
```

- [ ] **Step 4: Remove stale runtime-only assertions from CLI tests**

Keep `cmd/aegis` tests focused on CLI behavior. Runtime behavior should now be asserted under `internal/runtime`.

- [ ] **Step 5: Run CLI tests**

Run: `go test ./cmd/aegis`
Expected: PASS.

### Task 3: Verify behavior and clean up integration edges

**Files:**
- Modify: `internal/runtime/*.go`
- Modify: `internal/runtime/runtime_test.go`
- Modify: `cmd/aegis/main_test.go`

- [ ] **Step 1: Run the full targeted runtime surface**

Run: `go test ./cmd/aegis ./internal/runtime ./internal/...`
Expected: PASS, or a narrowed set of failures caused by moved helpers or package visibility issues.

- [ ] **Step 2: Fix any package boundary issues with minimal adapter code**

Examples include exported helper names, injected constructors, or test-only seams needed to preserve current behavior without pushing process concerns back into `cmd/aegis`.

```go
var newProxyServer = func(deps proxy.Dependencies) interface{ Handler() http.Handler } {
	return proxy.NewServer(deps)
}
```

- [ ] **Step 3: Run the full repository test suite**

Run: `go test ./...`
Expected: PASS.

- [ ] **Step 4: Inspect the resulting diff for architectural drift**

Check that:

- `cmd/aegis` no longer owns generation lifecycle,
- `internal/runtime` owns startup, reload, listeners, and shutdown,
- moved tests assert runtime behavior in the new package,
- no user-visible behavior changed unintentionally.

- [ ] **Step 5: Commit the refactor**

Run:

```bash
git add cmd/aegis/main.go cmd/aegis/main_test.go cmd/aegis/reload.go internal/runtime docs/superpowers/plans/2026-05-08-aegis-runtime-assembly.md
git commit -m "refactor: extract runtime assembly module"
```
