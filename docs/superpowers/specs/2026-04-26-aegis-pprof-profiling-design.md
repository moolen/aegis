# Aegis Pprof Profiling Design

## Summary

This slice adds an opt-in `pprof` surface to Aegis so performance investigations
can use real runtime profiles instead of only external latency and throughput
signals. The initial goal is to capture CPU, heap, goroutine, and blocking
profiles at the current deployed MITM knee and use that evidence to guide the
follow-on HTTP/2 work.

The `pprof` surface must be:

- disabled by default
- bound to a separate listener
- restricted to localhost-only addresses by validation
- operationally simple to enable during perf and staging work

This slice does **not** add HTTP/2 itself. It creates the profiling substrate
needed to make the HTTP/2 design evidence-driven.

## Goals

- Add standard Go `pprof` handlers behind explicit config.
- Keep the profiling surface off by default.
- Ensure the profiling listener cannot bind to non-localhost addresses.
- Make it easy to capture profiles during `perf/` runs.
- Produce one real MITM knee profile after implementation.

## Non-Goals

- No always-on profiling.
- No profiling on the metrics listener, admin listener, or proxy listener.
- No remote profiling auth model in this slice.
- No dashboards or long-term profile storage.
- No HTTP/2 transport changes in this slice.

## Config Shape

Add a new top-level config section:

```yaml
pprof:
  enabled: true
  listen: "127.0.0.1:6060"
```

Validation rules:

- `pprof.enabled: false` means the listener is not created.
- When `pprof.enabled: true`, `pprof.listen` is required.
- `pprof.listen` must resolve to a localhost-only bind:
  - `127.0.0.1:<port>`
  - `[::1]:<port>`
  - `localhost:<port>`
- wildcard or non-localhost binds are invalid.
- `pprof.listen` must not equal `proxy.listen`, `metrics.listen`, or
  `admin.listen`.

## Runtime Design

Add a dedicated `pprof` server alongside the existing proxy, metrics, and admin
servers.

Behavior:

- only starts when `pprof.enabled` is true
- serves the standard `net/http/pprof` endpoints
- logs startup and shutdown like the other listeners
- shuts down with the rest of the process
- is not part of readiness or liveness

The simplest route is a dedicated `http.ServeMux` that registers the standard
handlers:

- `/debug/pprof/`
- `/debug/pprof/profile`
- `/debug/pprof/heap`
- `/debug/pprof/goroutine`
- `/debug/pprof/block`
- `/debug/pprof/mutex`
- `/debug/pprof/trace`

## Operational Flow

The main use case is:

1. Enable `pprof` locally or in a staging-like environment.
2. Start Aegis with the current perf config.
3. Run the relevant `k6` scenario.
4. Capture one or more profiles from the localhost-only `pprof` listener.
5. Analyze the profile before changing runtime behavior.

The first profiling target is the deployed MITM path near the current knee.

## Repo Surface

Likely files to change:

- `internal/config/config.go`
- `internal/config/config_test.go`
- `internal/metrics/server.go` or a new profiling server file if cleaner
- `cmd/aegis/main.go`
- `cmd/aegis/main_test.go`
- `README.md`
- `aegis.example.yaml`
- `perf/README.md`

## Testing

### Config Tests

- `pprof.enabled: true` with missing `listen` fails validation
- non-localhost binds fail validation
- listener collisions with proxy/metrics/admin fail validation
- valid localhost binds pass

### Runtime Tests

- enabling `pprof` creates a server that responds on `/debug/pprof/`
- disabling `pprof` does not create the server
- shutdown closes the profiling server cleanly

## Deliverable

This slice is complete when:

- the `pprof` listener exists behind explicit config
- validation enforces localhost-only binding and listener separation
- docs explain how to capture profiles
- one real profile can be collected against the MITM perf scenario

## Follow-On Slice

Once profiling is available, the next design/implementation slice is HTTP/2
support for both:

- client-to-Aegis on the MITM/decrypted HTTPS path
- Aegis-to-upstream HTTPS on pooled shared transports

That slice must prove real multiplexing and improved concurrency behavior, not
just ALPN negotiation.
