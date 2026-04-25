# Aegis Performance Baseline Package Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a repo-native `k6` load-test package that can run reproducible local and Kind/Helm performance baselines for HTTP, CONNECT passthrough, and CONNECT MITM traffic.

**Architecture:** The package will live under `perf/` and use explicit `k6` scenarios, deterministic config templates, and small orchestration scripts rather than a generic benchmarking framework. Local mode will run against subprocess Aegis and synthetic upstreams; Kind mode will deploy the existing Helm chart and drive the same logical scenarios against the in-cluster service.

**Tech Stack:** Go, `k6`, shell scripts, Makefile targets, Helm, Kind, Docker, Kubernetes, existing Aegis e2e fixtures.

---

## File Map

### New files
- `perf/README.md` — operator-facing documentation for running and interpreting baseline scenarios.
- `perf/k6/http.js` — `k6` script for plain HTTP policy-allowed traffic.
- `perf/k6/connect_passthrough.js` — `k6` script for HTTPS traffic through CONNECT passthrough.
- `perf/k6/connect_mitm.js` — `k6` script for HTTPS traffic through CONNECT MITM.
- `perf/config/local-http.yaml` — local Aegis config for the HTTP scenario.
- `perf/config/local-connect-passthrough.yaml` — local Aegis config for the passthrough scenario.
- `perf/config/local-connect-mitm.yaml` — local Aegis config for the MITM scenario.
- `perf/config/kind-http-values.yaml` — Helm values overlay for the HTTP scenario.
- `perf/config/kind-connect-passthrough-values.yaml` — Helm values overlay for the passthrough scenario.
- `perf/config/kind-connect-mitm-values.yaml` — Helm values overlay for the MITM scenario.
- `perf/scripts/common.sh` — shared shell helpers for tool checks, result directories, and metric capture.
- `perf/scripts/run-local-http.sh` — orchestrate local HTTP baseline.
- `perf/scripts/run-local-connect-passthrough.sh` — orchestrate local passthrough baseline.
- `perf/scripts/run-local-connect-mitm.sh` — orchestrate local MITM baseline.
- `perf/scripts/run-kind-http.sh` — orchestrate Kind HTTP baseline.
- `perf/scripts/run-kind-connect-passthrough.sh` — orchestrate Kind passthrough baseline.
- `perf/scripts/run-kind-connect-mitm.sh` — orchestrate Kind MITM baseline.
- `perf/scripts/fixtures.go` — small Go helper binary for synthetic upstream fixtures and result-oriented local bootstrapping.
- `perf/scripts/fixtures_test.go` — focused Go tests for fixture wiring where practical.
- `perf/.gitignore` — ignore `results/` artifacts.

### Modified files
- `Makefile` — add `perf-*` targets.
- `README.md` — document the existence of the baseline package and point to `perf/README.md`.

## Task 1: Create the perf directory structure and shared conventions

**Files:**
- Create: `perf/.gitignore`
- Create: `perf/README.md`
- Modify: `README.md`

- [ ] **Step 1: Write the perf README skeleton and root doc reference**

Add a new section to `README.md` near the Development section pointing to the perf package:

```md
## Performance Baselines

The repository includes a `perf/` package for reproducible `k6`-based
performance baselines against both local/subprocess and Kind/Helm deployments.
See [perf/README.md](perf/README.md) for setup, scenario descriptions, and run
commands.
```

Create `perf/README.md` with the initial structure:

```md
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
```

Create `perf/.gitignore`:

```gitignore
results/
```

- [ ] **Step 2: Verify the docs and ignore file exist**

Run: `test -f perf/README.md && test -f perf/.gitignore && rg -n "Performance Baselines|perf/README.md" README.md perf/README.md`
Expected: paths and headings printed, exit code 0

- [ ] **Step 3: Commit the scaffolding docs**

```bash
git add README.md perf/README.md perf/.gitignore
git commit -m "docs: add perf baseline package overview"
```

## Task 2: Add the synthetic fixture helper for local baselines

**Files:**
- Create: `perf/scripts/fixtures.go`
- Create: `perf/scripts/fixtures_test.go`

- [ ] **Step 1: Write the failing fixture tests**

Create `perf/scripts/fixtures_test.go` with focused tests around the helper’s CLI contract and HTTP behavior. Use a package-local `main_test` style test that exercises helper functions, not shelling the whole binary. Include tests like:

```go
func TestHTTPFixtureServesConfiguredPath(t *testing.T) {
    srv := newHTTPFixture("/allowed", http.StatusNoContent)
    req := httptest.NewRequest(http.MethodGet, "http://fixture/allowed", nil)
    rec := httptest.NewRecorder()

    srv.ServeHTTP(rec, req)

    if rec.Code != http.StatusNoContent {
        t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
    }
}

func TestHTTPFixtureRejectsUnexpectedPath(t *testing.T) {
    srv := newHTTPFixture("/allowed", http.StatusNoContent)
    req := httptest.NewRequest(http.MethodGet, "http://fixture/denied", nil)
    rec := httptest.NewRecorder()

    srv.ServeHTTP(rec, req)

    if rec.Code != http.StatusNotFound {
        t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
    }
}

func TestFixtureConfigParsesTLSMode(t *testing.T) {
    cfg, err := parseFixtureConfig([]string{"-mode", "mitm", "-listen", "127.0.0.1:0", "-path", "/allowed"})
    if err != nil {
        t.Fatalf("parseFixtureConfig() error = %v", err)
    }
    if cfg.Mode != "mitm" {
        t.Fatalf("mode = %q, want %q", cfg.Mode, "mitm")
    }
}
```

- [ ] **Step 2: Run the fixture tests to verify they fail**

Run: `/usr/local/go/bin/go test ./perf/scripts -run 'Test(HTTPFixtureServesConfiguredPath|HTTPFixtureRejectsUnexpectedPath|FixtureConfigParsesTLSMode)' -v`
Expected: FAIL with missing symbols or package errors

- [ ] **Step 3: Implement the fixture helper minimally**

Create `perf/scripts/fixtures.go` as a small Go program with:

- `fixtureConfig` struct
- `parseFixtureConfig(args []string) (fixtureConfig, error)`
- `newHTTPFixture(path string, successStatus int) http.Handler`
- optional TLS startup path using generated or temp test certs for HTTPS fixtures
- `main()` that starts the requested listener and prints the bound address in a stable format

Core shape:

```go
package main

import (
    "flag"
    "fmt"
    "log"
    "net"
    "net/http"
)

type fixtureConfig struct {
    Mode   string
    Listen string
    Path   string
}

func parseFixtureConfig(args []string) (fixtureConfig, error) {
    fs := flag.NewFlagSet("fixtures", flag.ContinueOnError)
    cfg := fixtureConfig{}
    fs.StringVar(&cfg.Mode, "mode", "http", "http|passthrough|mitm")
    fs.StringVar(&cfg.Listen, "listen", "127.0.0.1:0", "listen address")
    fs.StringVar(&cfg.Path, "path", "/allowed", "allowed path")
    if err := fs.Parse(args); err != nil {
        return fixtureConfig{}, err
    }
    return cfg, nil
}

func newHTTPFixture(path string, successStatus int) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.URL.Path != path {
            http.NotFound(w, r)
            return
        }
        w.WriteHeader(successStatus)
    })
}

func main() {
    cfg, err := parseFixtureConfig(os.Args[1:])
    if err != nil {
        log.Fatal(err)
    }
    ln, err := net.Listen("tcp", cfg.Listen)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("LISTEN_ADDR=%s\n", ln.Addr().String())
    log.Fatal(http.Serve(ln, newHTTPFixture(cfg.Path, http.StatusNoContent)))
}
```

Keep the first implementation simple and local-target oriented; any HTTPS/TLS specifics can be added in the next task when the scenario scripts are wired.

- [ ] **Step 4: Run the fixture tests to verify they pass**

Run: `/usr/local/go/bin/go test ./perf/scripts -v`
Expected: PASS

- [ ] **Step 5: Commit the fixture helper**

```bash
git add perf/scripts/fixtures.go perf/scripts/fixtures_test.go
git commit -m "feat: add local perf fixture helper"
```

## Task 3: Add repo-native local Aegis perf configs and `k6` scenarios

**Files:**
- Create: `perf/config/local-http.yaml`
- Create: `perf/config/local-connect-passthrough.yaml`
- Create: `perf/config/local-connect-mitm.yaml`
- Create: `perf/k6/http.js`
- Create: `perf/k6/connect_passthrough.js`
- Create: `perf/k6/connect_mitm.js`

- [ ] **Step 1: Write the failing render/smoke test for local config presence**

Create or extend `perf/scripts/fixtures_test.go` with a simple filesystem presence test:

```go
func TestLocalPerfConfigTemplatesExist(t *testing.T) {
    paths := []string{
        "../config/local-http.yaml",
        "../config/local-connect-passthrough.yaml",
        "../config/local-connect-mitm.yaml",
        "../k6/http.js",
        "../k6/connect_passthrough.js",
        "../k6/connect_mitm.js",
    }
    for _, path := range paths {
        if _, err := os.Stat(path); err != nil {
            t.Fatalf("Stat(%q) error = %v", path, err)
        }
    }
}
```

- [ ] **Step 2: Run the smoke test to verify it fails**

Run: `/usr/local/go/bin/go test ./perf/scripts -run TestLocalPerfConfigTemplatesExist -v`
Expected: FAIL on missing files

- [ ] **Step 3: Add local config templates**

Create `perf/config/local-http.yaml` like:

```yaml
proxy:
  listen: "127.0.0.1:3128"
metrics:
  listen: "127.0.0.1:9090"
dns:
  cache_ttl: 30s
  timeout: 5s
  servers: []
  rebindingProtection:
    allowedCIDRs: ["127.0.0.0/8"]
policies:
  - name: perf-http
    subjects:
      cidrs: ["127.0.0.0/8"]
    egress:
      - fqdn: "127.0.0.1"
        ports: [18080]
        tls:
          mode: mitm
        http:
          allowedMethods: ["GET"]
          allowedPaths: ["/allowed"]
```

Create analogous passthrough and MITM configs with the right ports and TLS modes.

- [ ] **Step 4: Add `k6` scenario scripts**

Each script should take configuration from env vars and produce `handleSummary()` JSON/text output.

`perf/k6/http.js` shape:

```js
import http from 'k6/http';
import { check } from 'k6';

export const options = {
  vus: Number(__ENV.K6_VUS || 10),
  duration: __ENV.K6_DURATION || '30s',
};

export default function () {
  const proxyURL = __ENV.PROXY_URL;
  const targetURL = __ENV.TARGET_URL;
  const res = http.get(targetURL, {
    proxies: { http: proxyURL, https: proxyURL },
  });
  check(res, { 'status is 204': (r) => r.status === 204 });
}

export function handleSummary(data) {
  return {
    stdout: textSummary(data, { indent: ' ', enableColors: false }),
    [`${__ENV.RESULT_DIR}/summary.json`]: JSON.stringify(data, null, 2),
  };
}
```

Use the `k6/http` API similarly for the HTTPS scenarios, targeting the passthrough and MITM URLs. Keep them explicit instead of inventing a shared abstraction too early.

- [ ] **Step 5: Run the smoke test to verify presence**

Run: `/usr/local/go/bin/go test ./perf/scripts -run TestLocalPerfConfigTemplatesExist -v`
Expected: PASS

- [ ] **Step 6: Commit the configs and scripts**

```bash
git add perf/config perf/k6 perf/scripts/fixtures_test.go
git commit -m "feat: add local perf scenarios and configs"
```

## Task 4: Add shared shell helpers and local run scripts

**Files:**
- Create: `perf/scripts/common.sh`
- Create: `perf/scripts/run-local-http.sh`
- Create: `perf/scripts/run-local-connect-passthrough.sh`
- Create: `perf/scripts/run-local-connect-mitm.sh`

- [ ] **Step 1: Write the failing shell smoke test**

Add a small shell-oriented smoke test in `perf/scripts/fixtures_test.go` that only checks that expected script files exist and are executable after setup:

```go
func TestLocalPerfScriptsExist(t *testing.T) {
    paths := []string{
        "common.sh",
        "run-local-http.sh",
        "run-local-connect-passthrough.sh",
        "run-local-connect-mitm.sh",
    }
    for _, path := range paths {
        info, err := os.Stat(path)
        if err != nil {
            t.Fatalf("Stat(%q) error = %v", path, err)
        }
        if info.Mode()&0o111 == 0 {
            t.Fatalf("%q is not executable", path)
        }
    }
}
```

- [ ] **Step 2: Run the smoke test to verify it fails**

Run: `/usr/local/go/bin/go test ./perf/scripts -run TestLocalPerfScriptsExist -v`
Expected: FAIL on missing files

- [ ] **Step 3: Implement `common.sh` and local scripts**

`perf/scripts/common.sh` should provide helpers like:

```sh
#!/usr/bin/env bash
set -euo pipefail

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

new_result_dir() {
  local scenario="$1"
  local target="$2"
  local ts
  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  local dir="perf/results/${ts}-${scenario}-${target}"
  mkdir -p "$dir"
  printf '%s\n' "$dir"
}

capture_metrics() {
  local url="$1"
  local out="$2"
  curl -fsS "$url/metrics" > "$out"
}
```

Each local run script should:

- source `common.sh`
- require `k6`, `curl`, `docker` only if needed
- create a result dir
- start the fixture helper(s)
- start `./bin/aegis -config perf/config/...`
- wait for `/healthz`
- capture pre metrics
- run `k6`
- capture post metrics
- write a `meta.env` file with scenario parameters
- clean up child processes reliably

- [ ] **Step 4: Mark scripts executable and run the smoke test**

Run:

```bash
chmod +x perf/scripts/common.sh \
  perf/scripts/run-local-http.sh \
  perf/scripts/run-local-connect-passthrough.sh \
  perf/scripts/run-local-connect-mitm.sh
/usr/local/go/bin/go test ./perf/scripts -run TestLocalPerfScriptsExist -v
```

Expected: PASS

- [ ] **Step 5: Commit the local orchestration scripts**

```bash
git add perf/scripts/common.sh perf/scripts/run-local-http.sh perf/scripts/run-local-connect-passthrough.sh perf/scripts/run-local-connect-mitm.sh perf/scripts/fixtures_test.go
git commit -m "feat: add local perf orchestration scripts"
```

## Task 5: Add Kind overlays and Kind orchestration scripts

**Files:**
- Create: `perf/config/kind-http-values.yaml`
- Create: `perf/config/kind-connect-passthrough-values.yaml`
- Create: `perf/config/kind-connect-mitm-values.yaml`
- Create: `perf/scripts/run-kind-http.sh`
- Create: `perf/scripts/run-kind-connect-passthrough.sh`
- Create: `perf/scripts/run-kind-connect-mitm.sh`

- [ ] **Step 1: Write the failing Helm-render smoke test**

Add a presence test for Kind overlays and scripts in `perf/scripts/fixtures_test.go`:

```go
func TestKindPerfAssetsExist(t *testing.T) {
    paths := []string{
        "../config/kind-http-values.yaml",
        "../config/kind-connect-passthrough-values.yaml",
        "../config/kind-connect-mitm-values.yaml",
        "run-kind-http.sh",
        "run-kind-connect-passthrough.sh",
        "run-kind-connect-mitm.sh",
    }
    for _, path := range paths {
        if _, err := os.Stat(path); err != nil {
            t.Fatalf("Stat(%q) error = %v", path, err)
        }
    }
}
```

- [ ] **Step 2: Run the smoke test to verify it fails**

Run: `/usr/local/go/bin/go test ./perf/scripts -run TestKindPerfAssetsExist -v`
Expected: FAIL on missing files

- [ ] **Step 3: Add Helm overlays and Kind scripts**

Each overlay should configure the chart for the intended scenario, e.g. `perf-http` CIDR policy for a simple HTTP path, plus CA mount/config for MITM.

Each Kind script should:

- source `common.sh`
- require `k6`, `kind`, `kubectl`, `helm`, `docker`
- build or reuse `aegis:e2e-kind` / perf-local image
- create a Kind cluster or reuse a named perf cluster
- load the image
- install/upgrade the Helm release with the overlay
- wait for deployment readiness
- run `k6` either from the host against forwarded ports or via a containerized `k6` runner with the right network path
- capture pre/post metrics
- clean up or preserve the cluster depending on a documented flag

Keep the first cut simple and explicit. Reuse the existing Kind/e2e chart wiring patterns where practical.

- [ ] **Step 4: Run render and presence checks**

Run:

```bash
chmod +x perf/scripts/run-kind-http.sh \
  perf/scripts/run-kind-connect-passthrough.sh \
  perf/scripts/run-kind-connect-mitm.sh
/usr/local/go/bin/go test ./perf/scripts -run TestKindPerfAssetsExist -v
helm template aegis ./deploy/helm -f perf/config/kind-http-values.yaml >/tmp/perf-kind-http.out
helm template aegis ./deploy/helm -f perf/config/kind-connect-passthrough-values.yaml >/tmp/perf-kind-connect-passthrough.out
helm template aegis ./deploy/helm -f perf/config/kind-connect-mitm-values.yaml >/tmp/perf-kind-connect-mitm.out
```

Expected: test PASS, all `helm template` commands exit 0

- [ ] **Step 5: Commit the Kind assets**

```bash
git add perf/config/kind-http-values.yaml perf/config/kind-connect-passthrough-values.yaml perf/config/kind-connect-mitm-values.yaml perf/scripts/run-kind-http.sh perf/scripts/run-kind-connect-passthrough.sh perf/scripts/run-kind-connect-mitm.sh perf/scripts/fixtures_test.go
git commit -m "feat: add kind perf scenarios and overlays"
```

## Task 6: Add Makefile integration and end-to-end harness validation

**Files:**
- Modify: `Makefile`
- Modify: `perf/README.md`

- [ ] **Step 1: Write the failing Makefile expectation check**

Extend `perf/scripts/fixtures_test.go` with a filesystem/content check for the Makefile targets:

```go
func TestMakefileIncludesPerfTargets(t *testing.T) {
    data, err := os.ReadFile("../../Makefile")
    if err != nil {
        t.Fatalf("ReadFile() error = %v", err)
    }
    for _, target := range []string{
        "perf-local-http:",
        "perf-local-connect:",
        "perf-local-mitm:",
        "perf-kind-http:",
        "perf-kind-connect:",
        "perf-kind-mitm:",
    } {
        if !strings.Contains(string(data), target) {
            t.Fatalf("Makefile missing target %q", target)
        }
    }
}
```

- [ ] **Step 2: Run the Makefile check to verify it fails**

Run: `/usr/local/go/bin/go test ./perf/scripts -run TestMakefileIncludesPerfTargets -v`
Expected: FAIL because targets are missing

- [ ] **Step 3: Add Makefile targets and flesh out perf docs**

Add to `Makefile`:

```make
.PHONY: perf-local-http perf-local-connect perf-local-mitm perf-kind-http perf-kind-connect perf-kind-mitm

perf-local-http:
	./perf/scripts/run-local-http.sh

perf-local-connect:
	./perf/scripts/run-local-connect-passthrough.sh

perf-local-mitm:
	./perf/scripts/run-local-connect-mitm.sh

perf-kind-http:
	./perf/scripts/run-kind-http.sh

perf-kind-connect:
	./perf/scripts/run-kind-connect-passthrough.sh

perf-kind-mitm:
	./perf/scripts/run-kind-connect-mitm.sh
```

Extend `perf/README.md` with:

- warmup / steady-state / stress explanation
- local vs Kind usage
- output artifact examples
- note that CI should only validate harness execution, not fixed latency thresholds

- [ ] **Step 4: Run the Makefile/content validation**

Run:

```bash
/usr/local/go/bin/go test ./perf/scripts -run TestMakefileIncludesPerfTargets -v
make -n perf-local-http
make -n perf-kind-http
```

Expected: test PASS, `make -n` shows the expected script invocations

- [ ] **Step 5: Run a lightweight local harness smoke command**

Run: `./perf/scripts/run-local-http.sh`
Expected: exits 0 and writes a new `perf/results/<timestamp>-http-local/` directory with `summary.json`, `summary.txt`, `metrics-before.txt`, `metrics-after.txt`, and `meta.env`

- [ ] **Step 6: Run a lightweight Kind harness smoke command**

Run: `./perf/scripts/run-kind-http.sh`
Expected: exits 0 and writes a new `perf/results/<timestamp>-http-kind/` directory with the same artifact set

- [ ] **Step 7: Commit the integration layer**

```bash
git add Makefile perf/README.md perf/scripts/fixtures_test.go
git commit -m "feat: add perf baseline command surface"
```

## Task 7: Final verification and cleanup

**Files:**
- Verify only — no intended code changes

- [ ] **Step 1: Run the focused perf harness tests**

Run: `/usr/local/go/bin/go test ./perf/scripts -v`
Expected: PASS

- [ ] **Step 2: Run the main repo verification commands**

Run:

```bash
make test
make e2e
/usr/local/go/bin/go build ./...
helm template aegis ./deploy/helm >/tmp/aegis-perf-helm.out
```

Expected: all commands exit 0

- [ ] **Step 3: Run one explicit local perf target and one explicit Kind perf target through Makefile**

Run:

```bash
make perf-local-http
make perf-kind-http
```

Expected: both exit 0 and produce `perf/results/` artifacts

- [ ] **Step 4: Review git diff for unintended result artifacts**

Run: `git status --short`
Expected: no tracked result files under `perf/results/`; only intended source/doc changes staged or committed

- [ ] **Step 5: Commit any final doc or script polish**

```bash
git add perf Makefile README.md
git commit -m "test: verify perf baseline package"
```

Use this commit only if a final small cleanup is needed after verification. If not needed, skip this commit.
