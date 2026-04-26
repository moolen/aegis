# Aegis Performance Baselines

The `perf/` package runs reproducible `k6` baselines against Aegis in two environments:

- local subprocess runs driven by `perf/scripts/run-local-*.sh`
- Kind + Helm runs driven by `perf/scripts/run-kind-*.sh`

## Required Tools

- `go` (builds `bin/aegis` and the fixture helper on demand for local targets)
- `k6`
- `curl`
- `docker`
- `kind` (for Kind targets)
- `kubectl` (for Kind targets)
- `helm` (for Kind targets)
- `openssl` (for MITM and in-cluster TLS fixture setup)
- `base64` (for local MITM fixture trust material decoding)

## Scenarios

- HTTP proxy
- CONNECT passthrough
- CONNECT MITM

## Targets

- local / subprocess
- kind / helm

## Load Shape

The current `k6` scenarios use a constant-VU, fixed-duration profile controlled by `VUS`, `DURATION`, and `SLEEP_SECONDS`.

- warmup: start with shorter durations and lower `VUS` to validate wiring, certificates, proxy policy, and result capture
- steady-state: use the default or agreed baseline duration to compare runs over the same scenario and environment
- stress: increase `VUS` and/or duration in the same target to find saturation points and failure modes

These runs are baselines, not a separate benchmark framework. Keep the shape explicit in the command environment you record for each run.

## Local vs Kind

Use local targets when you want the fastest feedback loop against a subprocess Aegis binary and synthetic upstream fixtures:

- `make perf-local-http`
- `make perf-local-connect`
- `make perf-local-mitm`

Use Kind targets when you need Helm-rendered deployment behavior, Kubernetes networking, and image packaging in the loop:

- `make perf-kind-http`
- `make perf-kind-connect`
- `make perf-kind-mitm`

Local runs build `bin/aegis` and the fixture helper on demand, then start fixture processes directly. Kind runs build/load an image, deploy the chart, and port-forward the in-cluster service before invoking the same logical `k6` scenario.

## Outputs

Each run writes artifacts under `perf/results/<timestamp>-<scenario>-<target>/`:

- `summary.json`
- `summary.txt`
- `metrics-before.txt`
- `metrics-after.txt`
- `meta.env`

Typical artifact paths look like:

- `perf/results/20260425T120000Z-http-local/summary.json`
- `perf/results/20260425T120000Z-http-local/summary.txt`
- `perf/results/20260425T120000Z-connect-mitm-local/meta.env`
- `perf/results/20260425T120000Z-http-kind/port-forward.log`

Use `summary.json` for machine-readable metric review, `summary.txt` for the operator-facing `k6` summary, `metrics-before.txt` and `metrics-after.txt` to compare Aegis metrics snapshots, and `meta.env` to capture the run inputs that made the result reproducible.

## CI Guidance

CI should validate that the harness runs successfully and emits the expected artifacts for a scenario. It should not gate on fixed latency thresholds, because those numbers are environment-sensitive and better tracked as baselines or trend comparisons outside of CI pass/fail logic.

## Commands

- `make perf-local-http`
- `make perf-local-connect`
- `make perf-local-mitm`
- `make perf-kind-http`
- `make perf-kind-connect`
- `make perf-kind-mitm`
