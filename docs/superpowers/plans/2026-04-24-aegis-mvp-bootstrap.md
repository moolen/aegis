# Aegis MVP Bootstrap Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and publish a runnable Aegis MVP bootstrap repository with a basic HTTP/CONNECT proxy, config loading, metrics, CI, containerization, and deployment scaffolding.

**Architecture:** The bootstrap keeps the package structure from the design doc but only implements the Phase 1 foundation. `cmd/aegis` wires config, logging, DNS, metrics, and proxy packages into one process. Future identity and policy packages exist only as stable interfaces and types so later phases land without repo churn.

**Tech Stack:** Go 1.26, `net/http`, `log/slog`, Prometheus Go client, YAML v3, GitHub Actions, Docker, Terraform skeleton, Helm chart.

---

### Task 1: Initialize module and repository hygiene

**Files:**
- Create: `.gitignore`
- Create: `.editorconfig`
- Create: `go.mod`
- Create: `README.md`
- Create: `Makefile`

- [ ] **Step 1: Write the failing structure check mentally and define the exact repo metadata**

```text
Module path: github.com/moolen/aegis
Go version: 1.26
Core commands: build, test, lint, docker
```

- [ ] **Step 2: Create repo hygiene files and module definition**

```gitignore
# Binaries
bin/
dist/
coverage.out

# Go
*.test
*.out

# IDE / OS
.DS_Store
.idea/
.vscode/
```

```editorconfig
root = true

[*]
charset = utf-8
end_of_line = lf
insert_final_newline = true
indent_style = space
indent_size = 2
trim_trailing_whitespace = true

[*.go]
indent_style = tab
indent_size = 4
```

```go
module github.com/moolen/aegis

go 1.26
```

- [ ] **Step 3: Add developer commands and top-level documentation**

```makefile
.PHONY: build test lint docker fmt

build:
	go build ./...

test:
	go test ./...

lint:
	gofmt -w $(shell find . -name '*.go' -not -path './vendor/*')
	go test ./...

docker:
	docker build -t aegis:dev .

fmt:
	gofmt -w $(shell find . -name '*.go' -not -path './vendor/*')
```

```md
# Aegis

Aegis is an identity-aware HTTP egress proxy. This repository currently contains the MVP bootstrap: a runnable HTTP/CONNECT forward proxy, config loading, metrics, tests, CI, and deployment scaffolding.
```

- [ ] **Step 4: Run targeted checks for the initialized metadata**

Run: `go test ./...`
Expected: no packages to test yet, command exits successfully after later tasks add packages

- [ ] **Step 5: Commit**

```bash
git add .gitignore .editorconfig go.mod README.md Makefile
git commit -m "chore: initialize repository metadata"
```

### Task 2: Implement config package and example config

**Files:**
- Create: `internal/config/config.go`
- Create: `internal/config/config_test.go`
- Create: `aegis.example.yaml`

- [ ] **Step 1: Write failing tests for config loading and validation**

```go
func TestLoadValidConfig(t *testing.T) {
    cfg, err := Load(bytes.NewReader([]byte(`proxy:
  listen: ":3128"
metrics:
  listen: ":9090"
dns:
  cache_ttl: 30s
`)))
    if err != nil {
        t.Fatalf("Load() error = %v", err)
    }
    if cfg.Proxy.Listen != ":3128" {
        t.Fatalf("unexpected proxy listen %q", cfg.Proxy.Listen)
    }
}

func TestLoadRejectsMissingProxyListen(t *testing.T) {
    _, err := Load(bytes.NewReader([]byte(`metrics:
  listen: ":9090"
`)))
    if err == nil {
        t.Fatal("expected validation error")
    }
}
```

- [ ] **Step 2: Run config tests to verify they fail first**

Run: `go test ./internal/config -run TestLoad -v`
Expected: FAIL because `Load` is not defined yet

- [ ] **Step 3: Implement config structs, defaults, loader, and validation**

```go
type Config struct {
    Proxy   ProxyConfig   `yaml:"proxy"`
    Metrics MetricsConfig `yaml:"metrics"`
    DNS     DNSConfig     `yaml:"dns"`
}
```

Include defaults for `metrics.listen` and `dns.cache_ttl`, YAML decoding with strict known fields, and validation for required listen addresses.

- [ ] **Step 4: Add example config matching the MVP runtime**

```yaml
proxy:
  listen: ":3128"
metrics:
  listen: ":9090"
dns:
  cache_ttl: 30s
  timeout: 5s
  servers: []
```

- [ ] **Step 5: Run config tests to verify they pass**

Run: `go test ./internal/config -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go aegis.example.yaml
git commit -m "feat: add config loading and validation"
```

### Task 3: Implement metrics package

**Files:**
- Create: `internal/metrics/metrics.go`
- Create: `internal/metrics/server.go`
- Create: `internal/metrics/server_test.go`

- [ ] **Step 1: Write failing tests for health and metrics endpoints**

```go
func TestServerExposesHealthz(t *testing.T) {
    reg := prometheus.NewRegistry()
    srv := NewServer(":0", reg)
    ts := httptest.NewServer(srv.Handler())
    defer ts.Close()

    resp, err := http.Get(ts.URL + "/healthz")
    if err != nil {
        t.Fatalf("GET /healthz error = %v", err)
    }
    if resp.StatusCode != http.StatusOK {
        t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
    }
}
```

- [ ] **Step 2: Run metrics tests to verify they fail**

Run: `go test ./internal/metrics -run TestServerExposesHealthz -v`
Expected: FAIL because `NewServer` is not defined yet

- [ ] **Step 3: Implement Prometheus collectors and HTTP handler wiring**

```go
type Metrics struct {
    RequestsTotal       *prometheus.CounterVec
    ErrorsTotal         *prometheus.CounterVec
    RequestDuration     *prometheus.HistogramVec
    DNSResolutionsTotal *prometheus.CounterVec
    DNSDuration         prometheus.Histogram
}
```

Create a `Server` wrapper that exposes `/metrics` and `/healthz` via `http.ServeMux`.

- [ ] **Step 4: Run metrics tests to verify they pass**

Run: `go test ./internal/metrics -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/metrics/metrics.go internal/metrics/server.go internal/metrics/server_test.go
git commit -m "feat: add metrics server"
```

### Task 4: Implement DNS resolver package

**Files:**
- Create: `internal/dns/resolver.go`
- Create: `internal/dns/resolver_test.go`

**Test:**
- `internal/dns/resolver_test.go`

- [ ] **Step 1: Write failing tests for caching and lookup execution**

```go
func TestResolverCachesResults(t *testing.T) {
    calls := 0
    r := NewResolver(Config{CacheTTL: time.Minute}, func(ctx context.Context, host string) ([]net.IP, error) {
        calls++
        return []net.IP{net.ParseIP("127.0.0.1")}, nil
    }, slog.New(slog.NewTextHandler(io.Discard, nil)))

    _, _ = r.LookupNetIP(context.Background(), "example.com")
    _, _ = r.LookupNetIP(context.Background(), "example.com")

    if calls != 1 {
        t.Fatalf("resolver calls = %d, want 1", calls)
    }
}
```

- [ ] **Step 2: Run DNS tests to verify they fail**

Run: `go test ./internal/dns -run TestResolverCachesResults -v`
Expected: FAIL because `NewResolver` is not defined yet

- [ ] **Step 3: Implement resolver abstraction with cache and logging hooks**

```go
type Resolver struct {
    cacheTTL time.Duration
    lookupFn func(context.Context, string) ([]net.IP, error)
    logger   *slog.Logger
}
```

Provide `LookupNetIP(ctx, host)` with mutex-protected cache entries and log lookup outcomes.

- [ ] **Step 4: Run DNS tests to verify they pass**

Run: `go test ./internal/dns -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/dns/resolver.go internal/dns/resolver_test.go
git commit -m "feat: add dns resolver abstraction"
```

### Task 5: Implement proxy package with HTTP and CONNECT support

**Files:**
- Create: `internal/proxy/server.go`
- Create: `internal/proxy/server_test.go`

**Test:**
- `internal/proxy/server_test.go`

- [ ] **Step 1: Write failing smoke tests for HTTP proxying and CONNECT tunneling**

```go
func TestProxyForwardsHTTPRequests(t *testing.T) {
    upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusNoContent)
    }))
    defer upstream.Close()

    proxyServer := httptest.NewServer(NewServer(Dependencies{Resolver: newStaticResolver(t, upstream.URL)}).Handler())
    defer proxyServer.Close()

    client := &http.Client{Transport: &http.Transport{Proxy: func(*http.Request) (*url.URL, error) {
        return url.Parse(proxyServer.URL)
    }}}

    req, _ := http.NewRequest(http.MethodGet, upstream.URL, nil)
    resp, err := client.Do(req)
    if err != nil {
        t.Fatalf("Do() error = %v", err)
    }
    if resp.StatusCode != http.StatusNoContent {
        t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
    }
}
```

Also add a CONNECT smoke test using a local TCP listener and manual tunnel establishment.

- [ ] **Step 2: Run proxy tests to verify they fail**

Run: `go test ./internal/proxy -run TestProxy -v`
Expected: FAIL because `NewServer` and dependencies are not defined yet

- [ ] **Step 3: Implement proxy server, request handling, and upstream dialing**

```go
type Resolver interface {
    LookupNetIP(context.Context, string) ([]net.IP, error)
}

type Dependencies struct {
    Resolver Resolver
    Metrics  *metrics.Metrics
    Logger   *slog.Logger
}
```

Implement HTTP absolute-URL forwarding, `CONNECT` handling through connection hijacking, direct TCP dialing to resolved targets, and explicit `400` / `502` / `500` responses.

- [ ] **Step 4: Run proxy tests to verify they pass**

Run: `go test ./internal/proxy -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/proxy/server.go internal/proxy/server_test.go
git commit -m "feat: add HTTP and CONNECT proxy support"
```

### Task 6: Wire main program and future-facing package boundaries

**Files:**
- Create: `cmd/aegis/main.go`
- Create: `internal/identity/resolver.go`
- Create: `internal/policy/engine.go`

**Test:**
- Existing package tests exercised through `go test ./...`

- [ ] **Step 1: Define the future-facing identity and policy types**

```go
type Identity struct {
    Source   string
    Provider string
    Name     string
    Labels   map[string]string
}

type Resolver interface {
    Resolve(ip net.IP) (*Identity, error)
}
```

```go
type Decision struct {
    Allowed bool
    Policy  string
}
```

- [ ] **Step 2: Implement `main` wiring for config, logger, resolver, metrics, and HTTP servers**

```go
func main() {
    // parse flags
    // load config
    // construct slog JSON logger
    // construct metrics and DNS resolver
    // construct proxy server
    // start proxy and metrics servers
    // wait for signal and shut down cleanly
}
```

- [ ] **Step 3: Run full test suite and build to verify wiring**

Run: `go test ./... && go build ./cmd/aegis`
Expected: PASS and successful binary build

- [ ] **Step 4: Commit**

```bash
git add cmd/aegis/main.go internal/identity/resolver.go internal/policy/engine.go
git commit -m "feat: wire aegis bootstrap service"
```

### Task 7: Add deployment scaffolding and containerization

**Files:**
- Create: `Dockerfile`
- Create: `deploy/fargate/task-definition.json`
- Create: `deploy/fargate/main.tf`
- Create: `deploy/helm/Chart.yaml`
- Create: `deploy/helm/values.yaml`
- Create: `deploy/helm/templates/configmap.yaml`
- Create: `deploy/helm/templates/deployment.yaml`
- Create: `deploy/helm/templates/service.yaml`

- [ ] **Step 1: Write the exact deployment assumptions into the scaffolding content**

```text
Ports: proxy 3128, metrics 9090
Container image: ghcr.io/moolen/aegis:bootstrap
Config mount path: /etc/aegis/aegis.yaml
Current capability: generic HTTP/CONNECT proxy only
```

- [ ] **Step 2: Add a multi-stage Dockerfile and thin Fargate/Helm manifests**

```dockerfile
FROM golang:1.26 AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/aegis ./cmd/aegis

FROM gcr.io/distroless/static-debian12
COPY --from=build /out/aegis /usr/local/bin/aegis
ENTRYPOINT ["/usr/local/bin/aegis"]
```

Ensure the Terraform and Helm content references the correct ports and config path and documents missing production features tersely.

- [ ] **Step 3: Verify container build and Helm rendering assumptions**

Run: `docker build -t aegis:dev .`
Expected: PASS

Run: `helm template aegis ./deploy/helm >/tmp/aegis-helm.yaml`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add Dockerfile deploy/fargate/task-definition.json deploy/fargate/main.tf deploy/helm
git commit -m "feat: add deployment scaffolding"
```

### Task 8: Add CI workflow and final documentation

**Files:**
- Create: `.github/workflows/ci.yml`
- Modify: `README.md`

- [ ] **Step 1: Write the workflow checks explicitly**

```yaml
jobs:
  ci:
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
      - run: go test ./...
      - run: go build ./cmd/aegis
      - run: docker build -t aegis:ci .
```

- [ ] **Step 2: Update README with local run, test, and deployment scaffold notes**

```md
## Current status

This repository currently provides the MVP bootstrap. Identity-aware discovery, policy enforcement, and TLS inspection are planned but not implemented yet.
```

- [ ] **Step 3: Run the full verification set**

Run: `go test ./...`
Expected: PASS

Run: `go build ./...`
Expected: PASS

Run: `docker build -t aegis:dev .`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/ci.yml README.md
git commit -m "ci: add bootstrap verification workflow"
```

### Task 9: Create GitHub repository and push bootstrap state

**Files:**
- Modify: `.git/config`

- [ ] **Step 1: Verify local branch and remote target**

Run: `git status --short --branch`
Expected: `## main`

Run: `git remote -v`
Expected: no `origin` yet or existing origin to inspect

- [ ] **Step 2: Create the GitHub repository and attach the remote**

```bash
gh repo create moolen/aegis --public --source=. --remote=origin --push
```

If the repository already exists, set the remote explicitly:

```bash
git remote add origin https://github.com/moolen/aegis.git
```

- [ ] **Step 3: Verify push state**

Run: `git ls-remote --heads origin`
Expected: `refs/heads/main` exists on `origin`

- [ ] **Step 4: Commit any final local-only metadata if needed**

```bash
git status --short
```

Expected: clean working tree
