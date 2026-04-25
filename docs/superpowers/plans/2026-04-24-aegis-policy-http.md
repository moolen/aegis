# Aegis Plain HTTP Policy Enforcement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add policy-aware plain HTTP proxy enforcement to Aegis by extending config, implementing the policy engine, and denying or allowing HTTP requests before DNS and upstream dialing.

**Architecture:** This slice keeps the current bootstrap runtime and only changes the plain HTTP request path. `internal/config` gains the final policy schema and validation, `internal/policy` becomes the source of truth for ordered policy decisions, and `internal/proxy` uses an identity resolver plus policy engine to enforce allow/deny on absolute-URL HTTP proxy requests. The existing `CONNECT` path remains bootstrap-grade and structurally unchanged.

**Tech Stack:** Go 1.26, `net/http`, `path/filepath` glob matching, YAML v3, Prometheus Go client, `log/slog`.

---

### Task 1: Extend config schema for policies

**Files:**
- Modify: `internal/config/config.go`
- Modify: `internal/config/config_test.go`
- Modify: `aegis.example.yaml`

- [ ] **Step 1: Write failing config tests for valid and invalid policy shapes**

```go
func TestLoadValidPolicyConfig(t *testing.T) {
    cfg, err := Load(bytes.NewReader([]byte(`proxy:
  listen: ":3128"
policies:
  - name: allow-web
    identitySelector:
      matchLabels:
        app: web
    egress:
      - fqdn: "example.com"
        ports: [80]
        tls:
          mode: mitm
        http:
          allowedMethods: ["GET"]
          allowedPaths: ["/api/*"]
`)))
    if err != nil {
        t.Fatalf("Load() error = %v", err)
    }
    if len(cfg.Policies) != 1 {
        t.Fatalf("policies = %d, want 1", len(cfg.Policies))
    }
}

func TestLoadRejectsInvalidTLSMode(t *testing.T) {
    _, err := Load(bytes.NewReader([]byte(`proxy:
  listen: ":3128"
policies:
  - name: bad
    identitySelector:
      matchLabels: {}
    egress:
      - fqdn: "example.com"
        ports: [80]
        tls:
          mode: invalid
`)))
    if err == nil {
        t.Fatal("expected validation error")
    }
}

func TestLoadRejectsHTTPRulesForPassthrough(t *testing.T) {
    _, err := Load(bytes.NewReader([]byte(`proxy:
  listen: ":3128"
policies:
  - name: bad
    identitySelector:
      matchLabels: {}
    egress:
      - fqdn: "example.com"
        ports: [443]
        tls:
          mode: passthrough
        http:
          allowedMethods: ["GET"]
`)))
    if err == nil {
        t.Fatal("expected validation error")
    }
}
```

- [ ] **Step 2: Run config tests to verify the new cases fail first**

Run: `GOCACHE=$(pwd)/.cache/go-build GOMODCACHE=$(pwd)/.cache/mod go test ./internal/config -run 'TestLoad(ValidPolicyConfig|RejectsInvalidTLSMode|RejectsHTTPRulesForPassthrough)' -v`
Expected: FAIL because policy config fields and validation do not exist yet

- [ ] **Step 3: Implement policy config structs and validation in `internal/config/config.go`**

```go
type PolicyConfig struct {
    Name             string                 `yaml:"name"`
    IdentitySelector IdentitySelectorConfig `yaml:"identitySelector"`
    Egress           []EgressRuleConfig     `yaml:"egress"`
}

type IdentitySelectorConfig struct {
    MatchLabels map[string]string `yaml:"matchLabels"`
}

type EgressRuleConfig struct {
    FQDN string         `yaml:"fqdn"`
    Ports []int         `yaml:"ports"`
    TLS   TLSRuleConfig `yaml:"tls"`
    HTTP  *HTTPRuleConfig `yaml:"http,omitempty"`
}
```

Add `Policies []PolicyConfig` to `Config`, validate non-empty policy names, non-empty FQDNs, valid ports, valid TLS mode values, and disallow `http` rules under `passthrough`.

- [ ] **Step 4: Update `aegis.example.yaml` with one allowed plain-HTTP rule**

```yaml
policies:
  - name: allow-example
    identitySelector:
      matchLabels: {}
    egress:
      - fqdn: "example.com"
        ports: [80]
        tls:
          mode: mitm
        http:
          allowedMethods: ["GET"]
          allowedPaths: ["/*"]
```

- [ ] **Step 5: Run config tests to verify they pass**

Run: `GOCACHE=$(pwd)/.cache/go-build GOMODCACHE=$(pwd)/.cache/mod go test ./internal/config -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go aegis.example.yaml
git commit -m "feat: add policy config schema"
```

### Task 2: Implement the policy engine

**Files:**
- Modify: `internal/policy/engine.go`
- Create: `internal/policy/engine_test.go`

- [ ] **Step 1: Write failing unit tests for policy evaluation semantics**

```go
func TestEvaluateAllowsMatchingRule(t *testing.T) {
    engine, err := NewEngine([]config.PolicyConfig{{
        Name: "allow-web",
        IdentitySelector: config.IdentitySelectorConfig{MatchLabels: map[string]string{"app": "web"}},
        Egress: []config.EgressRuleConfig{{
            FQDN:  "example.com",
            Ports: []int{80},
            TLS:   config.TLSRuleConfig{Mode: "mitm"},
            HTTP: &config.HTTPRuleConfig{
                AllowedMethods: []string{"GET"},
                AllowedPaths:   []string{"/api/*"},
            },
        }},
    }})
    if err != nil {
        t.Fatalf("NewEngine() error = %v", err)
    }

    decision := engine.Evaluate(&identity.Identity{Labels: map[string]string{"app": "web"}}, "example.com", 80, http.MethodGet, "/api/users")
    if !decision.Allowed {
        t.Fatalf("decision.Allowed = false, want true")
    }
}

func TestEvaluateDeniesWhenNoPolicyMatches(t *testing.T) { ... }
func TestEvaluateFirstMatchWins(t *testing.T) { ... }
func TestEvaluateDeniesMethodMismatch(t *testing.T) { ... }
func TestEvaluateDeniesPathMismatch(t *testing.T) { ... }
func TestEvaluateMatchesFQDNGlob(t *testing.T) { ... }
```

- [ ] **Step 2: Run policy tests to verify they fail first**

Run: `GOCACHE=$(pwd)/.cache/go-build GOMODCACHE=$(pwd)/.cache/mod go test ./internal/policy -v`
Expected: FAIL because `NewEngine`, HTTP-aware `Evaluate`, and decision fields are not implemented yet

- [ ] **Step 3: Implement `internal/policy/engine.go`**

```go
type Engine struct {
    policies []Policy
}

type Decision struct {
    Allowed bool
    Policy  string
    Rule    string
    TLSMode string
}
```

Compile config into runtime policy structs, normalize methods to uppercase, use exact key/value selector matching, implement first-match-wins semantics, and use glob matching for FQDNs and paths.

- [ ] **Step 4: Run policy tests to verify they pass**

Run: `GOCACHE=$(pwd)/.cache/go-build GOMODCACHE=$(pwd)/.cache/mod go test ./internal/policy -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/policy/engine.go internal/policy/engine_test.go
git commit -m "feat: implement policy engine"
```

### Task 3: Expand identity support for request-time evaluation

**Files:**
- Modify: `internal/identity/resolver.go`
- Create: `internal/identity/resolver_test.go`

- [ ] **Step 1: Write failing tests for unknown identity behavior**

```go
func TestUnknownIdentityHasNoLabels(t *testing.T) {
    id := Unknown()
    if id == nil {
        t.Fatal("Unknown() returned nil")
    }
    if len(id.Labels) != 0 {
        t.Fatalf("labels = %v, want empty", id.Labels)
    }
}
```

- [ ] **Step 2: Run identity tests to verify they fail first**

Run: `GOCACHE=$(pwd)/.cache/go-build GOMODCACHE=$(pwd)/.cache/mod go test ./internal/identity -v`
Expected: FAIL because `Unknown` and helper behavior do not exist yet

- [ ] **Step 3: Implement unknown identity helpers and stable request-time types**

```go
func Unknown() *Identity {
    return &Identity{
        Source: "unknown",
        Name:   "unknown",
        Labels: map[string]string{},
    }
}
```

Keep the resolver interface intact, and add only the minimum helpers needed for proxy integration and tests.

- [ ] **Step 4: Run identity tests to verify they pass**

Run: `GOCACHE=$(pwd)/.cache/go-build GOMODCACHE=$(pwd)/.cache/mod go test ./internal/identity -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/identity/resolver.go internal/identity/resolver_test.go
git commit -m "feat: add request identity helpers"
```

### Task 4: Enforce plain HTTP policies in the proxy

**Files:**
- Modify: `internal/proxy/server.go`
- Modify: `internal/proxy/server_test.go`

- [ ] **Step 1: Write failing proxy tests for allow/deny behavior and pre-DNS short circuit**

```go
func TestProxyDeniesHTTPRequestsBeforeDNSLookup(t *testing.T) {
    dnsCalls := 0
    proxyServer := httptest.NewServer(NewServer(Dependencies{
        Resolver: countingResolver{lookup: map[string][]net.IP{"example.com": {net.ParseIP("127.0.0.1")}}, calls: &dnsCalls},
        IdentityResolver: staticIdentityResolver{identity: &identity.Identity{Labels: map[string]string{"app": "jobs"}}},
        PolicyEngine: mustPolicyEngine(t, []config.PolicyConfig{{
            Name: "allow-web",
            IdentitySelector: config.IdentitySelectorConfig{MatchLabels: map[string]string{"app": "web"}},
            Egress: []config.EgressRuleConfig{{
                FQDN: "example.com",
                Ports: []int{80},
                TLS: config.TLSRuleConfig{Mode: "mitm"},
                HTTP: &config.HTTPRuleConfig{AllowedMethods: []string{"GET"}, AllowedPaths: []string{"/*"}},
            }},
        }}),
        Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
    }).Handler())
    defer proxyServer.Close()

    resp, err := proxiedGET(proxyServer.URL, "http://example.com/")
    if err != nil {
        t.Fatalf("proxiedGET() error = %v", err)
    }
    if resp.StatusCode != http.StatusForbidden {
        t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusForbidden)
    }
    if dnsCalls != 0 {
        t.Fatalf("dnsCalls = %d, want 0", dnsCalls)
    }
}
```

Also add a matching allow test that confirms upstream receives the request, plus a deny test that confirms upstream is not hit.

- [ ] **Step 2: Run proxy tests to verify they fail first**

Run: `GOCACHE=$(pwd)/.cache/go-build GOMODCACHE=$(pwd)/.cache/mod go test ./internal/proxy -v`
Expected: FAIL because the proxy does not yet resolve identity or evaluate policy on HTTP requests

- [ ] **Step 3: Implement policy enforcement in `internal/proxy/server.go`**

```go
type IdentityResolver interface {
    Resolve(net.IP) (*identity.Identity, error)
}

type PolicyEngine interface {
    Evaluate(id *identity.Identity, fqdn string, port int, method string, path string) policy.Decision
}
```

For the HTTP path, derive the request identity from the configured resolver if present, fall back to `identity.Unknown()`, evaluate the decision before DNS lookup, return `403` on deny, and leave `CONNECT` behavior unchanged.

- [ ] **Step 4: Run proxy tests to verify they pass**

Run: `GOCACHE=$(pwd)/.cache/go-build GOMODCACHE=$(pwd)/.cache/mod go test ./internal/proxy -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/proxy/server.go internal/proxy/server_test.go
git commit -m "feat: enforce HTTP policy decisions"
```

### Task 5: Wire policy engine into the main process and docs

**Files:**
- Modify: `cmd/aegis/main.go`
- Modify: `README.md`

- [ ] **Step 1: Write the expected runtime wiring into the target design**

```go
engine, err := policy.NewEngine(cfg.Policies)
if err != nil {
    return 1
}

proxyHandler := proxy.NewServer(proxy.Dependencies{
    Resolver: resolver,
    PolicyEngine: engine,
    Logger: logger,
})
```

- [ ] **Step 2: Implement runtime wiring and documentation updates**

Update `main` to build the policy engine from config and inject it into the proxy. Update `README.md` to state that plain HTTP is policy-enforced while `CONNECT` remains bootstrap-grade.

- [ ] **Step 3: Run full verification**

Run: `GOCACHE=$(pwd)/.cache/go-build GOMODCACHE=$(pwd)/.cache/mod go test ./...`
Expected: PASS

Run: `GOCACHE=$(pwd)/.cache/go-build GOMODCACHE=$(pwd)/.cache/mod go build ./...`
Expected: PASS

Run: `docker build -t aegis:dev .`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add cmd/aegis/main.go README.md
git commit -m "feat: wire plain HTTP policy enforcement"
```

### Task 6: Publish updated branch state

**Files:**
- Modify: `.git/config`

- [ ] **Step 1: Verify branch state before push**

Run: `git status --short --branch`
Expected: clean working tree on `feat/mvp-bootstrap`

- [ ] **Step 2: Push the updated branch contents to remote `main`**

```bash
git push origin feat/mvp-bootstrap:main
```

- [ ] **Step 3: Verify remote head moved**

Run: `git ls-remote --heads origin`
Expected: `refs/heads/main` points at the latest local commit
