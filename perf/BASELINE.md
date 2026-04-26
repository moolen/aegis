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
| CONNECT passthrough | 10 | 8,352 | 1.049 | 1.404 | 6.753 | 0.00% |
| CONNECT MITM | 10 | 11,102 | 0.744 | 1.074 | 9.267 | 0.00% |
| CONNECT MITM | 25 | 14,958 | 1.395 | 2.372 | 384.886 | 0.00% |

### Kind Tunnel Status

All three deployed-shape traffic modes are now benchmarkable. The key fix was
removing `kubectl port-forward` from the proxy data path and switching the Kind
perf harness to fixed `NodePort` mappings, which avoids the websocket-forwarder
becoming the bottleneck under concurrent `CONNECT` load.

## Practical First-Pass Guidance

- For local and synthetic environments, Aegis handles roughly:
  - `~92k req/s` for plain HTTP at `100 VUs`
  - `~89k req/s` for CONNECT passthrough at `100 VUs`
  - `~89k req/s` for CONNECT MITM at `100 VUs`
- For the current Kind single-node deployment shape, plain HTTP is healthy at
  least through `~11.8k req/s` at `25 VUs`.
- For the current Kind single-node deployment shape, `CONNECT` passthrough is
  healthy at least through `~8.35k req/s` at `10 VUs`.
- For the current Kind single-node deployment shape, `CONNECT` MITM is healthy
  at least through `~15.0k req/s` at `25 VUs`.
- The next useful benchmark step is extending the same deployed-shape matrix to
  higher VU counts now that the MITM path is no longer blocked by the harness.

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
- Kind CONNECT passthrough healthy baseline:
  - `perf/results/20260426T093930Z-connect-passthrough-kind`
- Kind CONNECT MITM healthy baselines:
  - `perf/results/20260426T105942Z-connect-mitm-kind`
  - `perf/results/20260426T110230Z-connect-mitm-kind`
