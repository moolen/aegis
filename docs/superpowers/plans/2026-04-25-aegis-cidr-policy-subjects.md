# Aegis CIDR Policy Subjects Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add inline `subjects.cidrs` policy matching so policies can apply directly to request source IP ranges without relying on discovery.

**Architecture:** Extend the config schema with a third subject kind, compile CIDR strings once into parsed prefixes, and change policy subject evaluation from identity-only matching to identity-or-source-IP matching with OR semantics across Kubernetes, EC2, and CIDR subjects. Thread the request source IP through the proxy and admin simulation paths so CIDR-only policies work even when identity resolution returns unknown.

**Tech Stack:** Go, `net/netip`, `gopkg.in/yaml.v3`, existing config/policy/proxy test suites, existing subprocess and Kind e2e harnesses.

---

### Task 1: Add CIDR Subject Schema And Validation

**Files:**
- Modify: `internal/config/config.go`
- Modify: `internal/config/config_test.go`
- Modify: `aegis.example.yaml`
- Modify: `README.md`
- Modify: `deploy/helm/values.yaml`

- [ ] **Step 1: Write failing config tests for CIDR subjects**

Add table-driven coverage in `internal/config/config_test.go` for accepted CIDR subjects and invalid CIDR input:

```go
func TestLoadAcceptsCIDRPolicySubjects(t *testing.T) {
	cfgYAML := `proxy:
  listen: ":3128"
policies:
  - name: allow-office
    subjects:
      cidrs:
        - "10.20.0.0/16"
        - "2001:db8::/32"
    egress:
      - fqdn: "example.com"
        ports: [443]
        tls:
          mode: passthrough
`

	cfg, err := Load(bytes.NewReader([]byte(cfgYAML)))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got := cfg.Policies[0].Subjects.CIDRs; len(got) != 2 {
		t.Fatalf("Subjects.CIDRs length = %d, want 2", len(got))
	}
}

func TestLoadRejectsInvalidCIDRPolicySubjects(t *testing.T) {
	cfgYAML := `proxy:
  listen: ":3128"
policies:
  - name: invalid-cidr
    subjects:
      cidrs:
        - "10.20.0.0"
    egress:
      - fqdn: "example.com"
        ports: [443]
        tls:
          mode: passthrough
`

	_, err := Load(bytes.NewReader([]byte(cfgYAML)))
	if err == nil || !strings.Contains(err.Error(), "subjects.cidrs[0]") {
		t.Fatalf("Load() error = %v, want invalid cidr error", err)
	}
}
```

Also add coverage that a CIDR-only policy is valid:

```go
func TestLoadAcceptsCIDROnlyPolicySubjects(t *testing.T) { /* same shape, no discovery */ }
```

- [ ] **Step 2: Run the config tests to verify they fail**

Run: `go test ./internal/config -run 'TestLoad(AcceptsCIDRPolicySubjects|RejectsInvalidCIDRPolicySubjects|AcceptsCIDROnlyPolicySubjects)' -v`

Expected: FAIL because `subjects.cidrs` is not part of the schema yet.

- [ ] **Step 3: Implement the config schema and validation**

Extend `internal/config/config.go` with the new subject field:

```go
type PolicySubjectsConfig struct {
	Kubernetes *KubernetesSubjectConfig `yaml:"kubernetes,omitempty"`
	EC2        *EC2SubjectConfig        `yaml:"ec2,omitempty"`
	CIDRs      []string                 `yaml:"cidrs,omitempty"`
}
```

Tighten policy validation so CIDR subjects are first-class:

```go
for i, policy := range c.Policies {
	if policy.Subjects.Kubernetes == nil && policy.Subjects.EC2 == nil && len(policy.Subjects.CIDRs) == 0 {
		return fmt.Errorf("policies[%d].subjects must not be empty", i)
	}
	for j, cidr := range policy.Subjects.CIDRs {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			return fmt.Errorf("policies[%d].subjects.cidrs[%d] must not be empty", i, j)
		}
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return fmt.Errorf("policies[%d].subjects.cidrs[%d] must be a valid CIDR: %w", i, j, err)
		}
		policy.Subjects.CIDRs[j] = prefix.String()
	}
}
```

Normalize the CIDR list in place during validation so examples and runtime use canonical forms such as `10.20.0.0/16`.

- [ ] **Step 4: Run config tests to verify they pass**

Run: `go test ./internal/config -run 'TestLoad(AcceptsCIDRPolicySubjects|RejectsInvalidCIDRPolicySubjects|AcceptsCIDROnlyPolicySubjects)' -v`

Expected: PASS

- [ ] **Step 5: Update docs and examples**

Add one CIDR-only example to each of:

```yaml
policies:
  - name: allow-office
    subjects:
      cidrs:
        - "10.20.0.0/16"
    egress:
      - fqdn: "api.example.com"
        ports: [443]
        tls:
          mode: passthrough
```

Touch:
- `aegis.example.yaml`
- `README.md`
- `deploy/helm/values.yaml`

- [ ] **Step 6: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go aegis.example.yaml README.md deploy/helm/values.yaml
git commit -m "feat: add cidr policy subjects schema"
```

### Task 2: Teach The Policy Engine To Match Source CIDRs

**Files:**
- Modify: `internal/policy/engine.go`
- Modify: `internal/policy/engine_test.go`

- [ ] **Step 1: Write failing policy-engine tests for CIDR matching and OR semantics**

Add tests in `internal/policy/engine_test.go` covering CIDR-only and mixed-subject behavior:

```go
func TestEngineAllowsCIDRSubjectWithoutIdentity(t *testing.T) {
	engine, err := NewEngine([]config.PolicyConfig{{
		Name: "allow-office",
		Subjects: config.PolicySubjectsConfig{
			CIDRs: []string{"10.20.0.0/16"},
		},
		Egress: []config.EgressRuleConfig{{
			FQDN:  "example.com",
			Ports: []int{443},
			TLS:   config.TLSRuleConfig{Mode: "passthrough"},
		}},
	}})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	decision := engine.Evaluate(nil, netip.MustParseAddr("10.20.4.9"), "example.com", 443, "GET", "/")
	if decision == nil || !decision.Allowed {
		t.Fatalf("Evaluate() decision = %#v, want allowed", decision)
	}
}

func TestEngineUsesORAcrossSubjectKinds(t *testing.T) {
	engine, err := NewEngine([]config.PolicyConfig{{
		Name: "mixed",
		Subjects: config.PolicySubjectsConfig{
			Kubernetes: &config.KubernetesSubjectConfig{
				DiscoveryNames: []string{"cluster-a"},
				Namespaces:     []string{"frontend"},
				MatchLabels:    map[string]string{"app": "frontend"},
			},
			CIDRs: []string{"10.60.0.0/16"},
		},
		Egress: []config.EgressRuleConfig{{
			FQDN:  "example.com",
			Ports: []int{443},
			TLS:   config.TLSRuleConfig{Mode: "passthrough"},
		}},
	}})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	decision := engine.Evaluate(identity.Unknown(), netip.MustParseAddr("10.60.1.8"), "example.com", 443, "GET", "/")
	if decision == nil || !decision.Allowed {
		t.Fatalf("Evaluate() decision = %#v, want allowed via cidr", decision)
	}
}
```

Also add:

```go
func TestEngineDoesNotMatchOutsideCIDR(t *testing.T) { /* expect deny */ }
func TestEngineMatchesIPv6CIDRSubject(t *testing.T) { /* expect allow */ }
```

- [ ] **Step 2: Run the policy-engine tests to verify they fail**

Run: `go test ./internal/policy -run 'TestEngine(AllowsCIDRSubjectWithoutIdentity|UsesORAcrossSubjectKinds|DoesNotMatchOutsideCIDR|MatchesIPv6CIDRSubject)' -v`

Expected: FAIL because `Evaluate` and subject compilation do not know about source CIDRs.

- [ ] **Step 3: Implement CIDR subject compilation and matching**

Refactor `internal/policy/engine.go` so policy subject matching accepts both identity and source IP:

```go
type Subjects struct {
	kubernetes *KubernetesSubject
	ec2        *EC2Subject
	cidrs      []netip.Prefix
}

func (e *Engine) Evaluate(id *identity.Identity, sourceIP netip.Addr, fqdn string, port int, method string, reqPath string) *Decision
func (e *Engine) EvaluateConnect(id *identity.Identity, sourceIP netip.Addr, fqdn string, port int) *Decision
```

Compile CIDRs once:

```go
for _, raw := range cfg.CIDRs {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
	if err != nil {
		return Subjects{}, fmt.Errorf("cidr subjects: %w", err)
	}
	subjects.cidrs = append(subjects.cidrs, prefix)
}
```

Match with OR semantics:

```go
func (p Policy) matchesSubject(id *identity.Identity, sourceIP netip.Addr) bool {
	if p.subjects.matchesKubernetes(id) {
		return true
	}
	if p.subjects.matchesEC2(id) {
		return true
	}
	return p.subjects.matchesCIDR(sourceIP)
}

func (s Subjects) matchesCIDR(sourceIP netip.Addr) bool {
	if !sourceIP.IsValid() {
		return false
	}
	for _, prefix := range s.cidrs {
		if prefix.Contains(sourceIP) {
			return true
		}
	}
	return false
}
```

Keep first-policy-wins behavior unchanged by replacing only the subject-matching call site.

- [ ] **Step 4: Run the policy-engine tests to verify they pass**

Run: `go test ./internal/policy -run 'TestEngine(AllowsCIDRSubjectWithoutIdentity|UsesORAcrossSubjectKinds|DoesNotMatchOutsideCIDR|MatchesIPv6CIDRSubject)' -v`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/policy/engine.go internal/policy/engine_test.go
git commit -m "feat: match policy subjects by source cidr"
```

### Task 3: Thread Source IP Through Runtime, Proxy, And E2E Coverage

**Files:**
- Modify: `internal/proxy/server.go`
- Modify: `internal/proxy/server_test.go`
- Modify: `cmd/aegis/reload.go`
- Modify: `cmd/aegis/main_test.go`
- Modify: `e2e/smoke_test.go`
- Modify: `e2e/kind_smoke_test.go`

- [ ] **Step 1: Write failing integration tests for CIDR-only policy enforcement**

Add one proxy-level test in `internal/proxy/server_test.go`:

```go
func TestServerAllowsCIDRSubjectWithoutResolvedIdentity(t *testing.T) {
	engine, err := policy.NewEngine([]config.PolicyConfig{{
		Name: "allow-office",
		Subjects: config.PolicySubjectsConfig{
			CIDRs: []string{"10.20.0.0/16"},
		},
		Egress: []config.EgressRuleConfig{{
			FQDN:  "example.com",
			Ports: []int{80},
			TLS:   config.TLSRuleConfig{Mode: "mitm"},
			HTTP: &config.HTTPRuleConfig{
				AllowedMethods: []string{"GET"},
				AllowedPaths:   []string{"/allowed"},
			},
		}},
	}})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	// send request from 10.20.4.9 via a resolver that returns nil and expect upstream success
}
```

Add one runtime simulation test in `cmd/aegis/main_test.go`:

```go
func TestRuntimeManagerSimulateAllowsCIDRSubjectWithoutIdentity(t *testing.T) {
	resp, err := manager.Simulate(appmetrics.SimulationRequest{
		SourceIP: "10.20.4.9",
		FQDN:     "example.com",
		Port:     443,
		Protocol: "http",
		Method:   "GET",
		Path:     "/",
	})
	if err != nil {
		t.Fatalf("Simulate() error = %v", err)
	}
	if resp.Action != "allow" || resp.Reason != "policy_allowed" {
		t.Fatalf("Simulate() = %#v, want allow/policy_allowed", resp)
	}
}
```

- [ ] **Step 2: Run the integration tests to verify they fail**

Run:

```bash
go test ./internal/proxy -run 'TestServerAllowsCIDRSubjectWithoutResolvedIdentity' -v
go test ./cmd/aegis -run 'TestRuntimeManagerSimulateAllowsCIDRSubjectWithoutIdentity' -v
```

Expected: FAIL because the source IP is not being passed into policy evaluation.

- [ ] **Step 3: Thread source IP into policy evaluation**

Update `internal/proxy/server.go` so the request path passes the parsed remote IP into policy evaluation:

```go
sourceAddr, _ := netip.AddrFromSlice(remoteIP)
decision := s.deps.PolicyEngine.Evaluate(resolvedIdentity, sourceAddr, targetHost, targetPort, req.Method, req.URL.EscapedPath())
```

And for CONNECT:

```go
decision := s.deps.PolicyEngine.EvaluateConnect(resolvedIdentity, sourceAddr, host, port)
```

Update `cmd/aegis/reload.go` simulation logic the same way:

```go
sourceAddr, err := netip.ParseAddr(req.SourceIP)
if err != nil {
	return appmetrics.SimulationResponse{}, fmt.Errorf("sourceIP must be a valid IP address")
}
decision = generation.policyEngine.Evaluate(id, sourceAddr, req.FQDN, req.Port, req.Method, req.Path)
```

Adjust any internal interfaces in `internal/proxy/server.go` to match the new `Evaluate` and `EvaluateConnect` signatures.

- [ ] **Step 4: Add subprocess and Kind coverage**

Update `e2e/smoke_test.go` with a CIDR-only policy fixture:

```yaml
policies:
  - name: allow-local-range
    subjects:
      cidrs:
        - "127.0.0.1/32"
    egress:
      - fqdn: "upstream.internal"
        ports: [80]
        tls:
          mode: mitm
        http:
          allowedMethods: ["GET"]
          allowedPaths: ["/allowed"]
```

Assert:
- request from loopback is allowed even when identity resolution returns unknown
- request from a non-member IP remains denied

Update `e2e/kind_smoke_test.go` with one CIDR-scoped admin simulation or request path using pod IPs from the test namespace:

```yaml
subjects:
  cidrs:
    - "10.244.0.0/16"
```

Keep the existing retry-safe `kubectlExecPodEventually(...)` helper for admin simulation checks.

- [ ] **Step 5: Run the affected tests and then the full verification bundle**

Run:

```bash
go test ./internal/proxy -run 'TestServerAllowsCIDRSubjectWithoutResolvedIdentity' -v
go test ./cmd/aegis -run 'TestRuntimeManagerSimulateAllowsCIDRSubjectWithoutIdentity' -v
make e2e
make e2e-kind
make test
/usr/local/go/bin/go build ./...
helm template aegis ./deploy/helm
docker build -t aegis:dev .
```

Expected:
- targeted proxy/runtime tests PASS
- `make e2e` PASS
- `make e2e-kind` PASS
- full verification bundle PASS

- [ ] **Step 6: Commit**

```bash
git add internal/proxy/server.go internal/proxy/server_test.go cmd/aegis/reload.go cmd/aegis/main_test.go e2e/smoke_test.go e2e/kind_smoke_test.go
git commit -m "feat: enforce policies by source cidr"
```

## Self-Review

Spec coverage check:

- `subjects.cidrs` schema and validation: Task 1
- OR semantics across subject kinds: Task 2
- source-IP-based runtime behavior without discovery: Tasks 2 and 3
- IPv4/IPv6 coverage: Tasks 1 and 2
- docs/examples: Task 1
- integration/e2e coverage: Task 3

Placeholder scan:

- No `TODO`/`TBD` markers
- Every task names exact files
- Every test/implementation step includes concrete code or commands

Type consistency:

- `PolicySubjectsConfig.CIDRs []string` in config
- compiled form `[]netip.Prefix` in policy engine
- runtime API change consistently uses `netip.Addr` in `Evaluate` and `EvaluateConnect`
