# Aegis Performance Baseline

This is the first production-style capacity baseline captured from the in-repo
`k6` harness on `2026-04-26`.

These numbers are environment-specific. Treat them as a starting point for
capacity planning and regression tracking, not as universal product limits.

## Run Shape

- tool: `k6 v1.7.1`
- profile: constant VUs
- duration: `15s`
- think time: `SLEEP_SECONDS=0`
- targets:
  - local subprocess Aegis
  - Kind + Helm deployment

## Local Subprocess Baseline

All three local traffic paths remained healthy through `100 VUs` with zero
request failures.

| Scenario | VUs | Req/s | p50 ms | p95 ms | Max ms | Fail rate |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| HTTP | 25 | 58,483 | 0.258 | 0.641 | 4.715 | 0.00% |
| HTTP | 50 | 70,589 | 0.477 | 1.438 | 6.705 | 0.00% |
| HTTP | 100 | 92,391 | 0.639 | 2.636 | 16.858 | 0.00% |
| CONNECT passthrough | 25 | 49,141 | 0.325 | 0.822 | 4.545 | 0.00% |
| CONNECT passthrough | 50 | 68,842 | 0.483 | 1.482 | 10.377 | 0.00% |
| CONNECT passthrough | 100 | 88,680 | 0.667 | 2.670 | 24.214 | 0.00% |
| CONNECT MITM | 25 | 49,300 | 0.323 | 0.819 | 6.236 | 0.00% |
| CONNECT MITM | 50 | 67,947 | 0.492 | 1.494 | 8.724 | 0.00% |
| CONNECT MITM | 100 | 89,277 | 0.661 | 2.718 | 35.018 | 0.00% |

### Local Read

- The local single-process shape did not hit a clear knee by `100 VUs`.
- Plain HTTP is still the fastest path, but the tunnel paths are very close.
- MITM overhead is visible but small in this synthetic setup once certificate
  caching is warm.

## Kind + Helm Baseline

The deployed-shape HTTP path is healthy at the tested VU levels:

| Scenario | VUs | Req/s | p50 ms | p95 ms | Max ms | Fail rate |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| HTTP | 10 | 8,717 | 1.010 | 1.377 | 10.431 | 0.00% |
| HTTP | 25 | 11,799 | 1.954 | 2.837 | 21.748 | 0.00% |
| HTTP | 400 | 33,737 | 11.014 | 19.278 | 106.239 | 0.00% |
| HTTP | 800 | 34,363 | 22.155 | 33.141 | 71.109 | 0.00% |
| CONNECT passthrough | 10 | 8,352 | 1.049 | 1.404 | 6.753 | 0.00% |
| CONNECT passthrough | 50 | 39,026 | 1.034 | 1.953 | 82.463 | 0.00% |
| CONNECT passthrough | 100 | 43,062 | 2.183 | 3.797 | 89.678 | 0.00% |
| CONNECT passthrough | 200 | 51,356 | 4.195 | 7.230 | 90.127 | 0.00% |
| CONNECT passthrough | 400 | 53,913 | 5.948 | 14.197 | 48.706 | 0.00% |
| CONNECT passthrough | 800 | ~53,623 steady-state* | 6.129 | 14.544 | 57.756 | 0.00% |
| CONNECT MITM | 10 | 11,102 | 0.744 | 1.074 | 9.267 | 0.00% |
| CONNECT MITM | 25 | 14,958 | 1.395 | 2.372 | 384.886 | 0.00% |
| CONNECT MITM | 50 | 17,595 | 2.388 | 5.350 | 23.601 | 0.02% |
| CONNECT MITM | 100 | 18,466 | 4.746 | 11.103 | 36.077 | 0.00% |
| CONNECT MITM | 200 | 21,652 | 8.733 | 18.036 | 77.589 | 0.00% |
| CONNECT MITM | 250 | 20,470 | 10.803 | 22.259 | 87.880 | 0.00% |
| CONNECT MITM | 300 | 22,972 | 11.365 | 23.327 | 75.723 | 0.00% |
| CONNECT MITM | 400 | 23,946 | 15.772 | 28.726 | 81.224 | 0.00% |
| CONNECT MITM | 500 | 23,158 | 17.567 | 35.840 | 7074.320 | 0.14% |
| CONNECT MITM | 600 | 20,539 | 19.457 | 39.870 | 15076.571 | 0.00% |
| CONNECT MITM | 800 | 22,099 | 25.024 | 54.281 | 15080.460 | 0.00% |

### Kind Tunnel Status

All three deployed-shape traffic modes are now benchmarkable. The key fixes
were:

- removing `kubectl port-forward` from the proxy data path and switching the
  Kind perf harness to fixed `NodePort` mappings
- reusing pooled upstream transports for HTTP and MITM
- lowering normal allow-decision logs to `DEBUG`
- bounding per-host upstream connections on the pooled transport

With those changes, the deployed MITM path now exercises real client-side and
upstream-side HTTP/2 multiplexing and stays healthy through `800 VUs` on this
single-node Kind shape. The key harness and runtime fixes were:

- enabling HTTP/2 on the in-cluster HTTPS upstream fixture
- restarting Aegis after rotating the in-cluster MITM/upstream CA secret so the
  proxy picks up the new trust bundle before the run
- normalizing replay-safe empty-body requests before forwarding so Go's HTTP/2
  transport can recover cleanly from upstream `GOAWAY` frames

The practical knee is now above `800 VUs` on this environment, but the curve is
starting to bend: p95 rises from about `18 ms` at `200 VUs` to about `54 ms`
at `800 VUs`, and the `500 VU` run showed a small startup-only burst of reset
errors. The earlier
socket-exhaustion, stale-trust, and HTTP/2 retryability failures are no longer
the limiting factors in the current Kind MITM baseline.

## Practical First-Pass Guidance

- For local and synthetic environments, Aegis handles roughly:
  - `~92k req/s` for plain HTTP at `100 VUs`
  - `~89k req/s` for CONNECT passthrough at `100 VUs`
  - `~89k req/s` for CONNECT MITM at `100 VUs`
- For the current Kind single-node deployment shape, plain HTTP is healthy at
  least through `~34.4k req/s` at `800 VUs`.
- For the current Kind single-node deployment shape, `CONNECT` passthrough is
  healthy through `~53.9k req/s` at `400 VUs`, and steady-state throughput at
  `800 VUs` is still about `53.6k req/s`.
- For the current Kind single-node deployment shape, `CONNECT` MITM is healthy
  through `~22.1k req/s` at `800 VUs`.
- On this environment, `400 VUs` looks like a conservative production target
  for Kind MITM with strong latency headroom.
- `600-800 VUs` is still functional here, but p95 tail latency is materially
  worse and should be treated as stress territory rather than steady-state
  planning guidance.

## HTTP and Passthrough Resource Read

Using the run artifacts from the higher-concurrency HTTP and passthrough runs,
the deployed Aegis process looked like this at the end of each `15s`
steady-state window:

| Scenario | VUs | CPU Seconds Delta | Approx CPU Cores | RSS After | Goroutines After | Open FDs After |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| HTTP | 400 | 107.60 | 7.17 | 78.3 MiB | 266 | 137 |
| HTTP | 800 | 107.54 | 7.17 | 98.9 MiB | 266 | 137 |
| CONNECT passthrough | 400 | 57.86 | 3.86 | 86.8 MiB | 10 | 9 |
| CONNECT passthrough | 800 | 57.29 | 3.82 | 100.3 MiB | 10 | 9 |

Compared to MITM:

- plain HTTP drives more goroutines and open FDs because it uses the `net/http`
  server/request machinery directly under much higher request throughput
- CONNECT passthrough is the cheapest path by far in CPU and goroutine terms
- MITM remains the most expensive path, but its concurrency behavior is now
  stable and predictable

For the `800 VU` passthrough run, `k6` reported `389` interrupted VUs during
graceful stop because long-lived tunnels were still open after the `15s` active
window. Request failure rate stayed at `0`, and the more honest throughput read
for that run is `804,348 / 15s ≈ 53.6k req/s`, not the lower `iterations.rate`
value that includes drain time.

## Resource Read At Higher Concurrency

Using the run artifacts from the `250/300/400 VU` MITM runs, the deployed Aegis
process looked like this at the end of each `15s` steady-state window:

| Scenario | VUs | CPU Seconds Delta | Approx CPU Cores | RSS After | Goroutines After | Open FDs After |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| CONNECT MITM | 250 | 151.37 | 10.09 | 101.4 MiB | 13 | 12 |
| CONNECT MITM | 300 | 163.91 | 10.93 | 109.3 MiB | 13 | 12 |
| CONNECT MITM | 400 | 166.83 | 11.12 | 129.1 MiB | 15 | 14 |
| CONNECT MITM | 500 | 166.10 | 11.07 | 141.6 MiB | 14 | 13 |
| CONNECT MITM | 600 | 167.78 | 11.19 | 147.6 MiB | 13 | 12 |
| CONNECT MITM | 800 | 170.03 | 11.34 | 199.4 MiB | 14 | 13 |

These are not cluster-wide numbers. They come from the Aegis process metrics in
`metrics-before.txt` and `metrics-after.txt`:

- `process_cpu_seconds_total`
- `process_resident_memory_bytes`
- `process_open_fds`
- `go_goroutines`

On this machine, the first useful sizing read is:

- CPU, not memory, is the dominant resource at higher MITM concurrency
- memory growth from `250 -> 800 VUs` is still moderate relative to throughput
- goroutine and FD counts remain low and stable, which is a good sign that the
  HTTP/2 multiplexing path is no longer spraying connections or leaking work
- latency, not correctness, is the first signal to watch as concurrency rises

## Profiling Snapshot

With the new localhost-only `pprof` listener enabled on an isolated local MITM
run, Aegis handled `2,900,190` successful requests in `30s` at `200 VUs` with
`0%` failures and p95 around `4.72 ms`.

The useful profile reads from that run were:

- heap: about `5.1 MiB` in-use, dominated by startup/runtime allocations rather
  than request-path growth
- goroutines: stable at `8`, with no sign of unbounded goroutine growth under
  sustained MITM load

The CPU profile endpoint responded successfully, but in this specific local
environment it returned a zero-sample profile even while the load run was
active. That means the `pprof` surface is wired correctly and usable for heap
and goroutine inspection today, but CPU hotspot attribution still needs a
follow-up capture in staging or a different local runtime environment before it
can be treated as trustworthy tuning data.

The same limitation still showed up on the Kind MITM `250 VU` run: the CPU
profile endpoint responded, but the captured profile again contained zero
samples. Heap and goroutine profiles were still useful. The Kind heap snapshot
at `250 VUs` showed about `31.7 MiB` in-use, with the largest live buckets in:

- `runtime.mallocgc`
- `io.copyBuffer`
- `bufio.NewWriterSize`
- `net/http.(*http2ClientConn).addStreamLocked`
- `github.com/moolen/aegis/internal/proxy.(*Server).handleMITMHTTPRequest`

## Artifacts

Representative result directories:

- local HTTP `25/50/100 VUs`:
  - `perf/results/20260426T091835Z-http-local`
  - `perf/results/20260426T091926Z-http-local`
  - `perf/results/20260426T092017Z-http-local`
- local CONNECT passthrough `25/50/100 VUs`:
  - `perf/results/20260426T091852Z-connect-passthrough-local`
  - `perf/results/20260426T091943Z-connect-passthrough-local`
  - `perf/results/20260426T092034Z-connect-passthrough-local`
- local CONNECT MITM `25/50/100 VUs`:
  - `perf/results/20260426T091909Z-connect-mitm-local`
  - `perf/results/20260426T092000Z-connect-mitm-local`
  - `perf/results/20260426T092052Z-connect-mitm-local`
- Kind HTTP `10/25 VUs`:
  - `perf/results/20260426T092122Z-http-kind`
  - `perf/results/20260426T092759Z-http-kind`
  - `perf/results/20260426T172952Z-http-kind`
  - `perf/results/20260426T173244Z-http-kind`
- Kind CONNECT passthrough healthy baseline:
  - `perf/results/20260426T093930Z-connect-passthrough-kind`
  - `perf/results/20260426T093452Z-connect-passthrough-kind`
  - `perf/results/20260426T094308Z-connect-passthrough-kind`
  - `perf/results/20260426T173313Z-connect-passthrough-kind`
  - `perf/results/20260426T173349Z-connect-passthrough-kind`
- Kind CONNECT MITM healthy baselines:
  - `perf/results/20260426T105942Z-connect-mitm-kind`
  - `perf/results/20260426T110230Z-connect-mitm-kind`
  - `perf/results/20260426T124259Z-connect-mitm-kind`
  - `perf/results/20260426T125207Z-connect-mitm-kind`
  - `perf/results/20260426T125636Z-connect-mitm-kind`
  - `perf/results/20260426T130238Z-connect-mitm-kind`
  - `perf/results/20260426T163344Z-connect-mitm-kind`
  - `perf/results/20260426T163824Z-connect-mitm-kind`
  - `perf/results/20260426T163854Z-connect-mitm-kind`
  - `perf/results/20260426T165137Z-connect-mitm-kind`
  - `perf/results/20260426T165537Z-connect-mitm-kind`
  - `perf/results/20260426T165611Z-connect-mitm-kind`
  - `perf/results/20260426T170204Z-connect-mitm-kind`
  - `perf/results/20260426T170533Z-connect-mitm-kind`
  - `perf/results/20260426T170606Z-connect-mitm-kind`
- isolated local MITM `pprof` capture:
  - `/tmp/aegis-pprof-isolated.lfVQAn/result`

\* `CONNECT` passthrough at `800 VUs` completed the `15s` active load window
cleanly with `0` request failures, but many tunnels were still draining during
`k6` graceful stop. The listed throughput is the steady-state `iterations / 15s`
value rather than the raw `iterations.rate` from the full extended run time.
