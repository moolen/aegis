# Aegis Performance Baseline Package

**Status:** Draft  
**Date:** 2026-04-25

## Goal

Add a production-style load-test package that can establish repeatable baseline numbers for Aegis across the main runtime paths:

- plain HTTP proxy
- `CONNECT` passthrough
- `CONNECT` MITM

The package must support both:

- **local/subprocess** execution against a locally launched Aegis instance and synthetic upstreams
- **Kind/Helm** execution against the deployed chart shape in a local Kubernetes cluster

This is a baseline and capacity package, not a full production benchmarking platform.

## Scope

### In scope

- repo-native `k6` scenarios for the three main traffic paths
- local orchestration for synthetic upstreams + local Aegis
- Kind orchestration for image load + Helm deploy + scenario execution
- stable result output files for later comparison
- operator-facing docs for how to run the benchmarks and interpret the results
- Aegis metrics snapshots before/after runs to correlate client and server views

### Out of scope

- Fargate or cloud-hosted benchmarking
- automatic scaling recommendations
- long-running soak tests
- pprof automation or deep profiling
- dashboard/alert provisioning
- discovery churn/load tests
- external internet benchmarks with CDN/DNS variability

## Repo Shape

### `perf/k6/`

Scenario files:

- `http.js`
- `connect_passthrough.js`
- `connect_mitm.js`

Each script should accept configuration through environment variables so the same scenario can target either local or Kind deployments.

### `perf/config/`

Configuration templates and overlays:

- local Aegis config templates for each scenario class where needed
- Helm values overlays for Kind runs

The goal is to keep the performance harness configuration explicit and versioned.

### `perf/scripts/`

Small orchestration scripts to:

- check required tools (`k6`, `docker`, `kind`, `kubectl`, `helm` as appropriate)
- start/stop local upstream fixtures and local Aegis
- build/load the local Aegis image for Kind
- deploy/update the Helm release for Kind runs
- run `k6` with a consistent output layout
- capture pre/post metrics snapshots

These scripts should be simple, deterministic wrappers around existing repo behavior rather than a second control plane.

### `perf/results/`

Gitignored output directory containing per-run artifacts such as:

- `summary.json`
- text summary
- pre/post metrics snapshots
- optional raw `k6` output logs

### `Makefile`

Add explicit perf targets:

- `make perf-local-http`
- `make perf-local-connect`
- `make perf-local-mitm`
- `make perf-kind-http`
- `make perf-kind-connect`
- `make perf-kind-mitm`

Optional aggregate targets can be added later, but the first slice should keep each scenario individually addressable.

### `perf/README.md`

Document:

- required tools
- scenario descriptions
- warmup / steady-state / stress methodology
- how outputs are stored
- which numbers to compare between runs
- caveats around local hardware variance

## Scenario Methodology

Each scenario should follow a fixed three-phase pattern.

### 1. Warmup

Short run to stabilize the target:

- process startup settled
- TLS caches warmed where applicable
- connection reuse behavior established

### 2. Steady-state baseline

Timed run at fixed VUs / arrival rate intended to produce comparable baseline latency and throughput numbers.

### 3. Stress step

Higher concurrency or request rate to identify when error rate or latency degrades materially.

This first slice does not need dynamic threshold finding. It only needs fixed, documented stress levels that can be compared across runs.

## Initial Scenarios

### HTTP proxy

- send allowed plain HTTP GET traffic through Aegis to a synthetic upstream
- exercise policy evaluation on the normal HTTP path
- measure p50/p95/p99 latency, req/s, and error rate

### CONNECT passthrough

- send HTTPS traffic through Aegis with `tls.mode: passthrough`
- measure tunnel establishment and request latency through the passthrough path

### CONNECT MITM

- send HTTPS traffic through Aegis with `tls.mode: mitm`
- measure MITM overhead relative to passthrough
- capture cold vs warm certificate-cache effects with an explicit warmup and steady-state split

## Target Environments

### Local / subprocess mode

Use local synthetic upstreams and a locally launched `aegis` binary. This is the fast loop for development and repeatable baseline checks.

Characteristics:

- fastest feedback
- minimal infrastructure overhead
- easiest to debug when a perf scenario is broken

### Kind / Helm mode

Deploy the existing Helm chart into Kind, load the locally built image, and run the same logical scenarios against the in-cluster service.

Characteristics:

- closer to the deployed runtime shape
- includes Kubernetes networking and chart wiring overhead
- still controlled and reproducible enough for baseline comparison

This slice should benchmark the deployed shape, not discovery churn or cloud identity auth overhead.

## Runtime Data Collection

For each run, collect:

- `k6` summary output
- pre-run Aegis metrics snapshot
- post-run Aegis metrics snapshot
- scenario metadata such as target mode, concurrency, duration, and timestamp

Important metrics to compare:

- client-observed latency: p50/p95/p99
- throughput / req/s
- error rate
- Aegis request counters
- decision counters
- connect tunnel counters for CONNECT scenarios
- MITM certificate counters for MITM scenarios
- active connection/tunnel gauges where useful

## Tooling Assumptions

The package requires external tooling and should fail clearly when missing.

Required by scope:

- `k6`
- `docker`
- `kind` for Kind runs
- `kubectl` for Kind runs
- `helm` for Kind runs

Do not auto-install these from the repo. Document them and validate them at runtime.

## Success Criteria

This slice is successful when:

- a developer can run a local perf scenario and get reproducible artifacts
- a developer can run a Kind perf scenario and get reproducible artifacts
- the three main paths are covered: HTTP, CONNECT passthrough, CONNECT MITM
- results are stored in a stable format suitable for later comparison
- docs explain how to run and interpret the package without tribal knowledge

## Design Constraints

- use synthetic upstreams only for the initial baseline package
- keep the harness deterministic and boring
- avoid over-abstracting scripts; explicit scenario wiring is better than a complex generic framework
- keep local and Kind scenarios logically aligned so numbers remain comparable

## Testing

Testing for this slice should focus on harness integrity, not statistical assertions.

Coverage should include:

- script/config smoke checks where practical
- config/template rendering checks for Kind overlays
- a lightweight validation that scenario entrypoints and required env vars are wired correctly

The package should not assert exact latency or throughput values in CI, because those are environment-dependent. Instead, CI-style checks should verify the harness runs and produces outputs.
