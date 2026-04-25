# Aegis Discovery Registry And Explicit Policy Binding Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace global label-based identity selection with explicit discovery-provider-scoped policy subjects, and add cloud-native Kubernetes auth modes for EKS, GKE, and AKS while keeping `kubeconfig` for development.

**Architecture:** Extend the config schema so discovery becomes an explicit registry of named Kubernetes and EC2 providers, with Kubernetes auth mode selected in a unified `auth` block. Refactor the policy engine to match identities by provider binding first, then apply Kubernetes namespace and label selectors only for Kubernetes identities. Reuse the existing informer-based provider by teaching runtime construction how to build Kubernetes REST configs from `kubeconfig`, `inCluster`, `eks`, `gke`, and `aks`.

**Tech Stack:** Go, `gopkg.in/yaml.v3`, `k8s.io/client-go`, AWS SDK v2, Google and Azure SDK/client libraries as needed for managed-cluster auth, existing Go test suite.

---

### Task 1: Map The Schema Migration Surface

**Files:**
- Modify: `internal/config/config.go`
- Modify: `internal/config/config_test.go`
- Modify: `aegis.example.yaml`
- Modify: `README.md`
- Modify: `deploy/helm/values.yaml`

- [ ] **Step 1: Write failing config tests for the new schema**

Add table-driven coverage in `internal/config/config_test.go` for:

```go
func TestLoadAcceptsKubernetesDiscoveryAuthProviders(t *testing.T) {
	tests := []struct {
		name string
		yaml string
	}{
		{
			name: "kubeconfig",
			yaml: `proxy:
  listen: ":3128"
discovery:
  kubernetes:
    - name: dev
      auth:
        provider: kubeconfig
        kubeconfig: /tmp/dev.kubeconfig
        context: dev
policies:
  - name: allow-dev
    subjects:
      kubernetes:
        discoveryNames: ["dev"]
        namespaces: ["default"]
        matchLabels:
          app: web
    egress:
      - fqdn: "example.com"
        ports: [443]
        tls:
          mode: passthrough
`,
		},
		{
			name: "eks",
			yaml: `proxy:
  listen: ":3128"
discovery:
  kubernetes:
    - name: cluster-a
      auth:
        provider: eks
        region: eu-central-1
        clusterName: cluster-a
policies:
  - name: allow-cluster-a
    subjects:
      kubernetes:
        discoveryNames: ["cluster-a"]
        namespaces: ["frontend"]
        matchLabels:
          app: frontend
    egress:
      - fqdn: "api.stripe.com"
        ports: [443]
        tls:
          mode: passthrough
`,
		},
		{
			name: "gke",
			yaml: `proxy:
  listen: ":3128"
discovery:
  kubernetes:
    - name: cluster-b
      auth:
        provider: gke
        project: prod-project
        location: europe-west1
        clusterName: cluster-b
policies:
  - name: allow-cluster-b
    subjects:
      kubernetes:
        discoveryNames: ["cluster-b"]
        namespaces: ["frontend"]
        matchLabels:
          app: frontend
    egress:
      - fqdn: "example.com"
        ports: [443]
        tls:
          mode: passthrough
`,
		},
		{
			name: "aks",
			yaml: `proxy:
  listen: ":3128"
discovery:
  kubernetes:
    - name: cluster-c
      auth:
        provider: aks
        subscriptionID: 00000000-0000-0000-0000-000000000000
        resourceGroup: rg-platform
        clusterName: cluster-c
policies:
  - name: allow-cluster-c
    subjects:
      kubernetes:
        discoveryNames: ["cluster-c"]
        namespaces: ["frontend"]
        matchLabels:
          app: frontend
    egress:
      - fqdn: "example.com"
        ports: [443]
        tls:
          mode: passthrough
`,
		},
		{
			name: "in-cluster",
			yaml: `proxy:
  listen: ":3128"
discovery:
  kubernetes:
    - name: in-cluster
      auth:
        provider: inCluster
policies:
  - name: allow-in-cluster
    subjects:
      kubernetes:
        discoveryNames: ["in-cluster"]
        namespaces: ["default"]
        matchLabels:
          app: web
    egress:
      - fqdn: "example.com"
        ports: [80]
        tls:
          mode: mitm
        http:
          allowedMethods: ["GET"]
          allowedPaths: ["/*"]
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Load(bytes.NewReader([]byte(tt.yaml))); err != nil {
				t.Fatalf("Load() error = %v", err)
			}
		})
	}
}
```

Add explicit rejection coverage for:

```go
func TestLoadRejectsLegacyIdentitySelectorPolicySchema(t *testing.T) { /* ... */ }
func TestLoadRejectsUnknownKubernetesDiscoveryReference(t *testing.T) { /* ... */ }
func TestLoadRejectsUnknownEC2DiscoveryReference(t *testing.T) { /* ... */ }
func TestLoadRejectsMissingKubernetesAuthProviderFields(t *testing.T) { /* ... */ }
func TestLoadRejectsEmptyPolicySubjects(t *testing.T) { /* ... */ }
```

- [ ] **Step 2: Run config tests to verify they fail**

Run: `go test ./internal/config -run 'TestLoad(AcceptsKubernetesDiscoveryAuthProviders|RejectsLegacyIdentitySelectorPolicySchema|RejectsUnknownKubernetesDiscoveryReference|RejectsUnknownEC2DiscoveryReference|RejectsMissingKubernetesAuthProviderFields|RejectsEmptyPolicySubjects)' -v`

Expected: FAIL with unknown `auth` / `subjects` fields or missing validation.

- [ ] **Step 3: Implement the new config schema and validation**

Update `internal/config/config.go` to introduce:

```go
type KubernetesAuthConfig struct {
	Provider       string `yaml:"provider"`
	Kubeconfig     string `yaml:"kubeconfig"`
	Context        string `yaml:"context"`
	Region         string `yaml:"region"`
	Project        string `yaml:"project"`
	Location       string `yaml:"location"`
	ClusterName    string `yaml:"clusterName"`
	SubscriptionID string `yaml:"subscriptionID"`
	ResourceGroup  string `yaml:"resourceGroup"`
}

type KubernetesDiscoveryConfig struct {
	Name         string               `yaml:"name"`
	Auth         KubernetesAuthConfig `yaml:"auth"`
	Namespaces   []string             `yaml:"namespaces"`
	ResyncPeriod *time.Duration       `yaml:"resyncPeriod"`
}

type PolicySubjectsConfig struct {
	Kubernetes *KubernetesSubjectConfig `yaml:"kubernetes,omitempty"`
	EC2        *EC2SubjectConfig        `yaml:"ec2,omitempty"`
}

type KubernetesSubjectConfig struct {
	DiscoveryNames []string          `yaml:"discoveryNames"`
	Namespaces     []string          `yaml:"namespaces"`
	MatchLabels    map[string]string `yaml:"matchLabels"`
}

type EC2SubjectConfig struct {
	DiscoveryNames []string `yaml:"discoveryNames"`
}

type PolicyConfig struct {
	Name        string               `yaml:"name"`
	Enforcement string               `yaml:"enforcement"`
	Bypass      bool                 `yaml:"bypass"`
	Subjects    PolicySubjectsConfig `yaml:"subjects"`
	Egress      []EgressRuleConfig   `yaml:"egress"`
}
```

Validation requirements to implement:

```go
switch cfg.Auth.Provider {
case "kubeconfig":
	if strings.TrimSpace(cfg.Auth.Kubeconfig) == "" {
		return fmt.Errorf("discovery.kubernetes[%d].auth.kubeconfig is required for kubeconfig auth", i)
	}
case "incluster", "inCluster":
	// no extra required fields
case "eks":
	if strings.TrimSpace(cfg.Auth.Region) == "" || strings.TrimSpace(cfg.Auth.ClusterName) == "" {
		return fmt.Errorf("discovery.kubernetes[%d].auth.region and clusterName are required for eks auth", i)
	}
case "gke":
	if strings.TrimSpace(cfg.Auth.Project) == "" || strings.TrimSpace(cfg.Auth.Location) == "" || strings.TrimSpace(cfg.Auth.ClusterName) == "" {
		return fmt.Errorf("discovery.kubernetes[%d].auth.project, location, and clusterName are required for gke auth", i)
	}
case "aks":
	if strings.TrimSpace(cfg.Auth.SubscriptionID) == "" || strings.TrimSpace(cfg.Auth.ResourceGroup) == "" || strings.TrimSpace(cfg.Auth.ClusterName) == "" {
		return fmt.Errorf("discovery.kubernetes[%d].auth.subscriptionID, resourceGroup, and clusterName are required for aks auth", i)
	}
default:
	return fmt.Errorf("discovery.kubernetes[%d].auth.provider must be kubeconfig, inCluster, eks, gke, or aks", i)
}
```

Add policy subject validation:

```go
if len(policy.Subjects.Kubernetes.DiscoveryNames) == 0 && len(policy.Subjects.EC2.DiscoveryNames) == 0 {
	return fmt.Errorf("policies[%d].subjects must reference at least one discovery provider", i)
}
if policy.IdentitySelector.MatchLabels != nil {
	return fmt.Errorf("policies[%d].identitySelector is no longer supported; use subjects instead", i)
}
```

Resolve subject references against the discovery registry by kind during validation.

- [ ] **Step 4: Run config tests to verify they pass**

Run: `go test ./internal/config -v`

Expected: PASS

- [ ] **Step 5: Update shipped examples and docs to the new schema**

Modify `aegis.example.yaml`, `deploy/helm/values.yaml`, and `README.md` to replace:

- `discovery.kubernetes[].kubeconfig`
- `policies[].identitySelector`

with:

```yaml
discovery:
  kubernetes:
    - name: dev
      auth:
        provider: kubeconfig
        kubeconfig: /path/to/kubeconfig
        context: dev

policies:
  - name: allow-example
    subjects:
      kubernetes:
        discoveryNames: ["dev"]
        namespaces: ["default"]
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

- [ ] **Step 6: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go aegis.example.yaml README.md deploy/helm/values.yaml
git commit -m "feat: add discovery registry and policy subject schema"
```

### Task 2: Build Managed Kubernetes Auth Config Constructors

**Files:**
- Modify: `internal/identity/runtime.go`
- Modify: `internal/identity/runtime_test.go`
- Create: `internal/identity/kubernetes_auth.go`
- Create: `internal/identity/kubernetes_auth_test.go`

- [ ] **Step 1: Write failing tests for Kubernetes auth-mode runtime construction**

Add `internal/identity/kubernetes_auth_test.go` coverage for:

```go
func TestBuildKubernetesRESTConfigForKubeconfig(t *testing.T) { /* loads kubeconfig path + optional context */ }
func TestBuildKubernetesRESTConfigForInCluster(t *testing.T) { /* calls in-cluster builder */ }
func TestBuildKubernetesRESTConfigForEKS(t *testing.T) { /* uses region + clusterName through injected deps */ }
func TestBuildKubernetesRESTConfigForGKE(t *testing.T) { /* uses project + location + clusterName through injected deps */ }
func TestBuildKubernetesRESTConfigForAKS(t *testing.T) { /* uses subscriptionID + resourceGroup + clusterName through injected deps */ }
func TestBuildKubernetesRESTConfigRejectsUnknownAuthProvider(t *testing.T) { /* ... */ }
```

Use dependency injection instead of real cloud calls:

```go
type kubernetesAuthDeps struct {
	loadKubeconfig func(path string, context string) (*rest.Config, error)
	loadInCluster  func() (*rest.Config, error)
	loadEKS        func(ctx context.Context, region string, clusterName string) (*rest.Config, error)
	loadGKE        func(ctx context.Context, project string, location string, clusterName string) (*rest.Config, error)
	loadAKS        func(ctx context.Context, subscriptionID string, resourceGroup string, clusterName string) (*rest.Config, error)
}
```

- [ ] **Step 2: Run auth tests to verify they fail**

Run: `go test ./internal/identity -run 'TestBuildKubernetesRESTConfig' -v`

Expected: FAIL because the helper and provider-specific builders do not exist.

- [ ] **Step 3: Implement an auth-provider-aware Kubernetes REST config builder**

Create `internal/identity/kubernetes_auth.go` with:

```go
func buildKubernetesRESTConfig(ctx context.Context, cfg config.KubernetesDiscoveryConfig, deps kubernetesAuthDeps) (*rest.Config, error) {
	switch normalizeKubernetesAuthProvider(cfg.Auth.Provider) {
	case "kubeconfig":
		return deps.loadKubeconfig(cfg.Auth.Kubeconfig, cfg.Auth.Context)
	case "incluster":
		return deps.loadInCluster()
	case "eks":
		return deps.loadEKS(ctx, cfg.Auth.Region, cfg.Auth.ClusterName)
	case "gke":
		return deps.loadGKE(ctx, cfg.Auth.Project, cfg.Auth.Location, cfg.Auth.ClusterName)
	case "aks":
		return deps.loadAKS(ctx, cfg.Auth.SubscriptionID, cfg.Auth.ResourceGroup, cfg.Auth.ClusterName)
	default:
		return nil, fmt.Errorf("unsupported kubernetes auth provider %q", cfg.Auth.Provider)
	}
}
```

Keep the actual cloud-provider client logic behind small helpers so tests can fully mock them. If a cloud SDK package is required, isolate it in this file and keep `runtime.go` unaware of provider specifics.

- [ ] **Step 4: Wire the new helper into runtime provider construction**

Update `internal/identity/runtime.go` so `newKubernetesRuntimeProvider()` calls the new auth builder instead of reading `cfg.Kubeconfig` directly:

```go
restCfg, err := buildKubernetesRESTConfig(context.Background(), cfg, defaultKubernetesAuthDeps())
if err != nil {
	return RuntimeProvider{}, fmt.Errorf("load kubernetes rest config for %s: %w", cfg.Name, err)
}
```

Adjust existing tests in `internal/identity/runtime_test.go` to assert the auth block is forwarded correctly instead of the removed top-level `Kubeconfig` field.

- [ ] **Step 5: Run identity runtime tests to verify they pass**

Run: `go test ./internal/identity -run 'Test(BuildKubernetesRESTConfig|ExportedNewKubernetesRuntimeProvider|NewKubernetesRuntimeProvider)' -v`

Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/identity/runtime.go internal/identity/runtime_test.go internal/identity/kubernetes_auth.go internal/identity/kubernetes_auth_test.go
git commit -m "feat: add managed kubernetes auth builders"
```

### Task 3: Refactor Policy Matching To Use Explicit Subjects

**Files:**
- Modify: `internal/policy/engine.go`
- Modify: `internal/policy/engine_test.go`
- Modify: `internal/identity/types.go`
- Test: `internal/policy/engine_test.go`

- [ ] **Step 1: Write failing policy-engine tests for provider-scoped matching**

Add tests to `internal/policy/engine_test.go`:

```go
func TestEvaluateMatchesKubernetesSubjectForBoundProviderOnly(t *testing.T) {
	engine, err := NewEngine([]config.PolicyConfig{{
		Name: "frontend-egress",
		Subjects: config.PolicySubjectsConfig{
			Kubernetes: &config.KubernetesSubjectConfig{
				DiscoveryNames: []string{"cluster-a"},
				Namespaces:     []string{"frontend"},
				MatchLabels:    map[string]string{"app": "frontend"},
			},
		},
		Egress: []config.EgressRuleConfig{{
			FQDN:  "api.stripe.com",
			Ports: []int{443},
			TLS:   config.TLSRuleConfig{Mode: "passthrough"},
		}},
	}})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	allowed := engine.EvaluateConnect(&identity.Identity{
		Source:   "kubernetes",
		Provider: "cluster-a",
		Labels: map[string]string{
			"kubernetes.io/namespace": "frontend",
			"app":                     "frontend",
		},
	}, "api.stripe.com", 443)
	if !allowed.Allowed {
		t.Fatal("expected cluster-a identity to match")
	}

	denied := engine.EvaluateConnect(&identity.Identity{
		Source:   "kubernetes",
		Provider: "cluster-b",
		Labels: map[string]string{
			"kubernetes.io/namespace": "frontend",
			"app":                     "frontend",
		},
	}, "api.stripe.com", 443)
	if denied.Allowed {
		t.Fatal("expected cluster-b identity not to match cluster-a-scoped policy")
	}
}

func TestEvaluateMatchesSharedKubernetesSelectorAcrossMultipleProviders(t *testing.T) { /* cluster-a and cluster-b both allowed */ }
func TestEvaluateMatchesEC2ProviderBindingWithoutLabelSelector(t *testing.T) { /* source=ec2, provider=legacy-web */ }
func TestEvaluateSkipsPolicyWhenIdentitySourceHasNoMatchingSubject(t *testing.T) { /* kubernetes identity vs ec2-only policy */ }
```

- [ ] **Step 2: Run policy tests to verify they fail**

Run: `go test ./internal/policy -run 'TestEvaluate(MatchesKubernetesSubjectForBoundProviderOnly|MatchesSharedKubernetesSelectorAcrossMultipleProviders|MatchesEC2ProviderBindingWithoutLabelSelector|SkipsPolicyWhenIdentitySourceHasNoMatchingSubject)' -v`

Expected: FAIL because `subjects` are not compiled or evaluated.

- [ ] **Step 3: Refactor policy compilation and matching**

Update `internal/policy/engine.go` to replace `selector map[string]string` with explicit subjects:

```go
type Policy struct {
	name        string
	enforcement string
	bypass      bool
	subjects    Subjects
	egress      []Rule
}

type Subjects struct {
	kubernetes *KubernetesSubject
	ec2        *EC2Subject
}

type KubernetesSubject struct {
	discoveryNames map[string]struct{}
	namespaces     map[string]struct{}
	matchLabels    map[string]string
}

type EC2Subject struct {
	discoveryNames map[string]struct{}
}
```

Implement subject compilation:

```go
func compileSubjects(cfg config.PolicySubjectsConfig) Subjects {
	// build exact-match sets for discovery names and namespaces
}
```

Implement provider-scoped matching:

```go
func (p Policy) matchesIdentity(id *identity.Identity) bool {
	if id == nil {
		return false
	}

	switch id.Source {
	case "kubernetes":
		return p.subjects.matchesKubernetes(id)
	case "ec2":
		return p.subjects.matchesEC2(id)
	default:
		return false
	}
}
```

Kubernetes matching must require:

```go
providerMatch &&
namespaceMatch &&
labelsMatch
```

EC2 matching must require only:

```go
providerMatch
```

- [ ] **Step 4: Run the full policy test suite**

Run: `go test ./internal/policy -v`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/policy/engine.go internal/policy/engine_test.go internal/identity/types.go
git commit -m "feat: bind policies to explicit discovery subjects"
```

### Task 4: Update Runtime And Admin Surfaces For The New Discovery Semantics

**Files:**
- Modify: `cmd/aegis/main.go`
- Modify: `cmd/aegis/main_test.go`
- Modify: `internal/metrics/server.go`
- Modify: `internal/metrics/server_test.go`
- Modify: `internal/identity/composite.go`

- [ ] **Step 1: Write targeted runtime tests for multi-provider disambiguation**

Add/adjust tests in `cmd/aegis/main_test.go` and `internal/metrics/server_test.go` to cover:

```go
func TestRunBuildsPoliciesFromExplicitSubjectsSchema(t *testing.T) { /* valid config boots */ }
func TestRuntimeSimulationReturnsProviderScopedDecision(t *testing.T) { /* /admin/simulate reflects cluster binding */ }
```

Use the existing admin/runtime seams rather than full e2e in this task.

- [ ] **Step 2: Run targeted runtime tests to verify they fail**

Run: `go test ./cmd/aegis ./internal/metrics -run 'Test(RunBuildsPoliciesFromExplicitSubjectsSchema|RuntimeSimulationReturnsProviderScopedDecision)' -v`

Expected: FAIL until the new config schema flows through startup and admin simulation.

- [ ] **Step 3: Update runtime wiring to consume the new schema end to end**

Adjust startup code so:

- `config.Load()` output with `subjects` flows into `policy.NewEngine()`
- discovery provider names remain unchanged in resolved identities
- admin simulation uses the same provider-scoped policy evaluation path without compatibility shims

No new runtime behavior should be added here beyond using the new config shape consistently.

- [ ] **Step 4: Run targeted runtime tests to verify they pass**

Run: `go test ./cmd/aegis ./internal/metrics -v`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add cmd/aegis/main.go cmd/aegis/main_test.go internal/metrics/server.go internal/metrics/server_test.go internal/identity/composite.go
git commit -m "refactor: wire explicit discovery subjects through runtime"
```

### Task 5: Refresh End-To-End Coverage For The New Config Model

**Files:**
- Modify: `e2e/smoke_test.go`
- Modify: `e2e/protocol_matrix_test.go`
- Modify: `e2e/kind_smoke_test.go`
- Modify: `e2e/helpers_test.go`

- [ ] **Step 1: Write failing e2e cases that prove provider-scoped policy behavior**

Add subprocess coverage for:

```go
func TestPolicySubjectBindsToConfiguredKubernetesProviderName(t *testing.T) { /* same labels, different provider, only one allowed */ }
func TestPolicySubjectBindsToConfiguredEC2ProviderName(t *testing.T) { /* simulate ec2 identity dump/provider */ }
```

If the current subprocess harness cannot cleanly synthesize provider-specific identities, add a focused unit/integration seam instead of forcing a brittle cross-process fake.

Add or adjust Kind coverage so the Helm/chart examples use the new `subjects.kubernetes` schema and still prove real Kubernetes discovery enforcement.

- [ ] **Step 2: Run e2e tests to verify failures**

Run: `go test -tags e2e ./e2e/... -run 'TestPolicySubject' -v`

Expected: FAIL until test fixtures and runtime config are migrated.

- [ ] **Step 3: Migrate e2e fixtures and helpers to the new config**

Update inline config fixtures from:

```yaml
identitySelector:
  matchLabels:
    app: web
```

to:

```yaml
subjects:
  kubernetes:
    discoveryNames: ["cluster-a"]
    namespaces: ["default"]
    matchLabels:
      app: web
```

Keep tests focused on the new guarantee:

- same labels do not imply same policy scope across providers
- Kubernetes namespace selection is exact
- EC2 subject binding remains provider-only

- [ ] **Step 4: Run the verification suite**

Run:

```bash
make test
make e2e
make e2e-kind
go build ./...
helm template aegis ./deploy/helm
docker build -t aegis:dev .
```

Expected: all commands pass

- [ ] **Step 5: Commit**

```bash
git add e2e/smoke_test.go e2e/protocol_matrix_test.go e2e/kind_smoke_test.go e2e/helpers_test.go
git commit -m "test: cover explicit discovery policy binding"
```

## Self-Review

Spec coverage check:

- Discovery registry and provider names: covered by Task 1 and Task 4.
- Kubernetes auth modes `kubeconfig`, `inCluster`, `eks`, `gke`, `aks`: covered by Task 1 and Task 2.
- Explicit provider-scoped policy subjects: covered by Task 1 and Task 3.
- Runtime semantics for provider-first policy matching: covered by Task 3 and Task 4.
- Migration/docs/examples: covered by Task 1 and Task 5.
- Testing across config, runtime, and provider binding: covered by Tasks 1, 2, 3, and 5.

Placeholder scan:

- No `TODO`, `TBD`, or “similar to above” placeholders remain.
- Every task names exact files and concrete commands.

Type consistency check:

- `KubernetesAuthConfig`, `PolicySubjectsConfig`, `KubernetesSubjectConfig`, and `EC2SubjectConfig` are introduced in Task 1 and then referenced consistently in Tasks 2 and 3.
- The runtime helper `buildKubernetesRESTConfig()` is introduced in Task 2 and referenced consistently there.
- Policy matching uses `Subjects`, `KubernetesSubject`, and `EC2Subject` consistently after Task 3.
