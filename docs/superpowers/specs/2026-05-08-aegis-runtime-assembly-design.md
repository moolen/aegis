# Aegis Runtime Assembly Design

**Date:** 2026-05-08
**Status:** Approved for implementation

## Goal

Deepen the runtime assembly module so `cmd/aegis` becomes a thin CLI seam that
parses flags, constructs process context, and calls a single runtime entrypoint.

This slice extracts process startup, reload, listener lifecycle, and generation
orchestration into a dedicated runtime module with better locality and a
smaller interface.

## Scope

### In scope

- Introduce a new `internal/runtime` package as the application runtime module.
- Move process boot orchestration out of `cmd/aegis`.
- Move generation build, activation, reload, and retirement behind the runtime
  seam.
- Move listener and `http.Server` construction behind the runtime seam.
- Keep remote policy discovery snapshot carry-forward and runner lifecycle
  inside the runtime module.
- Preserve existing runtime behavior for startup, reload, shutdown, readiness,
  admin, metrics, and pprof endpoints.
- Shift lifecycle-oriented tests toward `internal/runtime`.

### Out of scope

- Changing proxy policy semantics.
- Changing identity discovery behavior or precedence rules.
- Changing metrics schemas or admin API payloads.
- Reworking the proxy request-flow module.
- Reworking the policy decision interface.

## Design Boundary

This refactor changes where runtime behavior lives, not what the shipped Aegis
process does.

The process must still:

- load config from disk,
- start proxy, metrics, admin, and pprof listeners as configured,
- support `SIGHUP` reload,
- preserve immutable listener config across reload,
- drain on shutdown using the configured grace period,
- keep remote policy discovery behavior intact across reload.

The change is architectural: runtime lifecycle stops being a CLI concern and
becomes the responsibility of a dedicated module.

## Module Shape

Add a new `internal/runtime` package with one small public interface:

- `Run(ctx context.Context, opts Options) error`

`Options` should carry only process-level inputs:

- config path,
- logger,
- signal or listener dependencies if needed for tests.

`cmd/aegis` should become a thin shell that:

- parses flags,
- builds the logger,
- creates the signal-aware root context,
- calls `runtime.Run(...)`,
- maps the returned error to an exit code.

Inside `internal/runtime`, organize the implementation around a few focused
modules:

- `app.go`
  Owns the control loop for startup, reload, server exit, and shutdown.
- `generation.go`
  Owns generation state, activation, retirement, and access to active runtime
  properties like readiness and shutdown grace period.
- `build.go`
  Compiles config into one generation: proxy dependencies, identity resolver,
  MITM engine, merged policy engine, and runtime adapters.
- `servers.go`
  Builds listeners and `http.Server` instances for proxy, metrics, admin, and
  pprof.
- `discovery.go`
  Owns remote policy discovery runner lifecycle and snapshot carry-forward.

Only `internal/runtime` should know what a generation is.

## Runtime Lifecycle

The runtime module should own this flow:

1. Load config from the requested path.
2. Validate runtime and reload invariants.
3. Build the initial generation in isolation.
4. Build listeners and servers from that generation.
5. Start configured servers.
6. Enter a control loop that reacts to:
   - server exit,
   - `SIGHUP`,
   - root context cancellation.
7. On reload:
   - load and validate the next config,
   - build the next generation without mutating the active generation,
   - carry forward eligible remote policy snapshots,
   - atomically activate the next generation,
   - retire the previous generation.
8. On shutdown:
   - stop accepting new requests,
   - shut down servers with the active generation grace period,
   - drain active tunnels,
   - retire the active generation.

This makes "run the application" the deep interface and keeps handler swapping,
policy discovery freezing, and generation retirement local to the runtime
module.

## Generation Seam

The runtime generation module should own:

- the active config,
- the active proxy handler,
- identity resolver and readiness checker,
- policy runtime and merged policies,
- MITM engine state,
- upstream HTTP transport,
- remote policy discovery runner,
- carried remote snapshots.

Generation transitions should follow a strict rule:

- build next generation completely before activation,
- if build fails, keep the current generation active,
- if activation fails, keep the current generation active,
- once activation succeeds, retire the previous generation.

The runtime module should preserve the existing atomic handler swap semantics,
but that behavior should no longer leak into `cmd/aegis`.

## Discovery Ownership

Remote policy discovery should remain inside the runtime module because it is
part of generation lifecycle, not an independent process concern.

`internal/runtime/discovery.go` should own:

- building the remote discovery runner,
- applying snapshots to the active generation,
- carrying forward snapshots across reload for matching sources,
- freezing and unfreezing remote policy updates during reload,
- cleaning up source metrics when sources are removed.

This keeps the seam real: one module owns both generation transitions and the
reload-time discovery rules that currently leak across multiple functions.

## Server Ownership

`internal/runtime/servers.go` should own:

- proxy listener construction, including Proxy Protocol wrapping,
- metrics listener construction,
- admin listener construction,
- pprof listener construction,
- `http.Server` construction for each listener,
- startup and shutdown helpers for those servers.

The runtime app module should decide when to start or stop servers, but the
details of how listeners and servers are assembled should stay behind this
seam.

This separates process lifecycle from transport assembly and prevents the CLI
from accumulating server-specific knowledge again.

## Error Handling

Error handling should concentrate at the runtime seam.

Startup:

- config load or validation failure returns an error immediately,
- generation build failure returns an error immediately,
- listener or server construction failure returns an error immediately.

Reload:

- next-config load or validation failure leaves the current generation active,
- next-generation build failure leaves the current generation active,
- activation failure leaves the current generation active,
- reload result metrics and logs are still emitted.

Shutdown:

- server shutdown errors should be returned from `Run`,
- generation retirement and cleanup errors should be logged and contained when
  they cannot safely change the process outcome.

This keeps callers from reconstructing lifecycle semantics themselves.

## Testing Strategy

Move lifecycle-oriented tests toward `internal/runtime`.

Add runtime-focused tests covering:

- initial startup succeeds with valid config,
- initial startup fails cleanly on config or build errors,
- reload rejects immutable listener changes,
- reload keeps the current generation active when next-generation build fails,
- reload activates the next generation and retires the previous generation on
  success,
- shutdown uses the active generation grace period,
- remote policy snapshots carry forward only for matching discovery sources,
- removed remote discovery sources clean up their metrics.

Keep `cmd/aegis` tests small and focused on:

- flag parsing,
- exit code mapping,
- calling the runtime entrypoint with the expected options.

The design is successful if the main lifecycle tests no longer need to assert
through a giant CLI-oriented module.

## Migration Plan

Implement this refactor in a few mechanical steps:

1. Create `internal/runtime` with a top-level `Run` entrypoint and move the
   existing process control loop there.
2. Move runtime manager and generation logic out of `cmd/aegis/reload.go` into
   runtime-owned files.
3. Move listener and server construction out of `cmd/aegis/main.go` into
   runtime-owned files.
4. Update `cmd/aegis` to call the new runtime entrypoint.
5. Move or rewrite lifecycle tests so the main coverage sits under
   `internal/runtime`.

This order keeps the seam stable while reducing the risk of behavior drift.

## Success Criteria

This slice is complete when:

- `cmd/aegis` is reduced to CLI parsing and runtime invocation,
- `internal/runtime` owns process startup, reload, and shutdown,
- generation build and activation logic no longer lives in `cmd/aegis`,
- listener and server assembly no longer lives in `cmd/aegis`,
- existing runtime behavior is preserved,
- lifecycle tests primarily target `internal/runtime`,
- repository tests and builds pass after the refactor.
