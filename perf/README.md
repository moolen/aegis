# Aegis Performance Baselines

## Required Tools

- `k6`
- `docker`
- `kind` (for Kind targets)
- `kubectl` (for Kind targets)
- `helm` (for Kind targets)

## Scenarios

- HTTP proxy
- CONNECT passthrough
- CONNECT MITM

## Targets

- local / subprocess
- kind / helm

## Outputs

Each run writes artifacts under `perf/results/<timestamp>-<scenario>-<target>/`:

- `summary.json`
- `summary.txt`
- `metrics-before.txt`
- `metrics-after.txt`
- `meta.env`

## Commands

- `make perf-local-http`
- `make perf-local-connect`
- `make perf-local-mitm`
- `make perf-kind-http`
- `make perf-kind-connect`
- `make perf-kind-mitm`
