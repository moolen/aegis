# Aegis Kubernetes Identity Provider Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a real informer-backed Kubernetes identity provider package and config support that can resolve pod IPs into the unified Aegis `Identity` model, without changing the currently shipped runtime wiring.

**Architecture:** This slice extends config with `discovery.kubernetes`, adds a Kubernetes provider in `internal/identity`, and keeps its lifecycle explicit with `Start(ctx)` plus `Resolve(ip)`. The provider owns informer startup, pod-to-identity translation, and an in-memory IP map. `cmd/aegis/main.go` and proxy wiring remain unchanged so the shipped runtime behavior does not change yet.

**Tech Stack:** Go 1.26, `client-go` informers and fake clientset, `log/slog`, YAML v3.

---

### Task 1: Extend config for Kubernetes discovery

**Files:**
- Modify: `internal/config/config.go`
- Modify: `internal/config/config_test.go`

- [ ] **Step 1: Write failing config tests for Kubernetes discovery entries**

```go
func TestLoadValidKubernetesDiscoveryConfig(t *testing.T) {
    cfg, err := Load(bytes.NewReader([]byte(`proxy:
  listen: ":3128"
policies:
  - name: allow-example
    identitySelector:
      matchLabels: {}
    egress:
      - fqdn: "example.com"
        ports: [80]
        tls:
          mode: mitm
discovery:
  kubernetes:
    - name: cluster-a
      kubeconfig: /tmp/kubeconfig
      namespaces: ["default", "prod"]
      resyncPeriod: 30s
`)))
    if err != nil {
        t.Fatalf("Load() error = %v", err)
    }
    if len(cfg.Discovery.Kubernetes) != 1 {
        t.Fatalf("kubernetes entries = %d, want 1", len(cfg.Discovery.Kubernetes))
    }
}

func TestLoadRejectsKubernetesDiscoveryWithoutName(t *testing.T) { ... }
func TestLoadRejectsEmptyKubernetesNamespaceEntry(t *testing.T) { ... }
func TestLoadRejectsNonPositiveKubernetesResyncPeriod(t *testing.T) { ... }
```

- [ ] **Step 2: Run config tests to verify they fail first**

Run: `GOCACHE=$(pwd)/.cache/go-build GOMODCACHE=$(pwd)/.cache/mod go test ./internal/config -run 'TestLoad(ValidKubernetesDiscoveryConfig|RejectsKubernetesDiscoveryWithoutName|RejectsEmptyKubernetesNamespaceEntry|RejectsNonPositiveKubernetesResyncPeriod)' -v`
Expected: FAIL because `discovery.kubernetes` config fields and validation do not exist yet

- [ ] **Step 3: Implement config structs and validation for `discovery.kubernetes`**

```go
type DiscoveryConfig struct {
    Kubernetes []KubernetesDiscoveryConfig `yaml:"kubernetes"`
}

type KubernetesDiscoveryConfig struct {
    Name         string        `yaml:"name"`
    Kubeconfig   string        `yaml:"kubeconfig"`
    Namespaces   []string      `yaml:"namespaces"`
    ResyncPeriod time.Duration `yaml:"resyncPeriod"`
}
```

Add `Discovery DiscoveryConfig` to `Config`, validate non-empty discovery names, reject empty namespace strings, and reject non-positive `ResyncPeriod` when it is explicitly set.

- [ ] **Step 4: Run config tests to verify they pass**

Run: `GOCACHE=$(pwd)/.cache/go-build GOMODCACHE=$(pwd)/.cache/mod go test ./internal/config -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go
git commit -m "feat: add kubernetes discovery config"
```

### Task 2: Add Kubernetes provider construction and lifecycle

**Files:**
- Create: `internal/identity/kubernetes.go`
- Create: `internal/identity/kubernetes_test.go`
- Modify: `go.mod`
- Modify: `go.sum`

- [ ] **Step 1: Write failing tests for provider startup and basic resolution**

```go
func TestKubernetesProviderResolvesCreatedPod(t *testing.T) {
    client := fake.NewSimpleClientset()
    provider, err := NewKubernetesProvider(KubernetesProviderConfig{
        Name:         "cluster-a",
        Client:       client,
        Namespaces:   []string{"default"},
        ResyncPeriod: time.Second,
    }, slog.New(slog.NewTextHandler(io.Discard, nil)))
    if err != nil {
        t.Fatalf("NewKubernetesProvider() error = %v", err)
    }

    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()
    if err := provider.Start(ctx); err != nil {
        t.Fatalf("Start() error = %v", err)
    }

    _, _ = client.CoreV1().Pods("default").Create(ctx, &corev1.Pod{
        ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "default", Labels: map[string]string{"app": "web"}},
        Status: corev1.PodStatus{PodIP: "10.0.0.10"},
    }, metav1.CreateOptions{})

    requireEventuallyIdentity(t, provider, "10.0.0.10")
}
```

Also add a failing test that `Resolve` returns `nil` for an unknown IP.

- [ ] **Step 2: Run provider tests to verify they fail first**

Run: `GOCACHE=$(pwd)/.cache/go-build GOMODCACHE=$(pwd)/.cache/mod go test ./internal/identity -run 'TestKubernetesProvider(ResolvesCreatedPod|ReturnsNilForUnknownIP)' -v`
Expected: FAIL because the provider implementation and dependencies do not exist yet

- [ ] **Step 3: Add the provider skeleton, explicit lifecycle, and dependencies**

```go
type KubernetesProvider struct {
    name       string
    namespaces map[string]struct{}
    informers  []cache.SharedIndexInformer
    logger     *slog.Logger

    mu   sync.RWMutex
    byIP map[string]*Identity
}

func NewKubernetesProvider(cfg KubernetesProviderConfig, logger *slog.Logger) (*KubernetesProvider, error) { ... }
func (p *KubernetesProvider) Start(ctx context.Context) error { ... }
func (p *KubernetesProvider) Resolve(ip net.IP) (*Identity, error) { ... }
```

Use `client-go` fakeable interfaces, keep startup explicit, and populate the informer list without wiring runtime code in `main`.

- [ ] **Step 4: Add dependencies and verify the package compiles**

Run: `GOCACHE=$(pwd)/.cache/go-build GOMODCACHE=$(pwd)/.cache/mod go mod tidy`
Expected: PASS with `client-go` and Kubernetes API deps added to `go.mod` / `go.sum`

Run: `GOCACHE=$(pwd)/.cache/go-build GOMODCACHE=$(pwd)/.cache/mod go test ./internal/identity -run 'TestKubernetesProvider(ResolvesCreatedPod|ReturnsNilForUnknownIP)' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/identity/kubernetes.go internal/identity/kubernetes_test.go go.mod go.sum
git commit -m "feat: add kubernetes identity provider skeleton"
```

### Task 3: Implement informer-driven map maintenance semantics

**Files:**
- Modify: `internal/identity/kubernetes.go`
- Modify: `internal/identity/kubernetes_test.go`

- [ ] **Step 1: Write failing tests for update/delete/IP reuse and namespace labeling**

```go
func TestKubernetesProviderRemovesDeletedPod(t *testing.T) { ... }
func TestKubernetesProviderReplacesChangedPodIP(t *testing.T) { ... }
func TestKubernetesProviderInjectsNamespaceLabel(t *testing.T) { ... }
func TestKubernetesProviderIgnoresPodsWithoutIP(t *testing.T) { ... }
```

Include one test that deletes pod A, creates pod B with the same IP, and asserts the resolved identity becomes `namespace-b/pod-b` with the new label set.

- [ ] **Step 2: Run identity tests to verify they fail first**

Run: `GOCACHE=$(pwd)/.cache/go-build GOMODCACHE=$(pwd)/.cache/mod go test ./internal/identity -v`
Expected: FAIL because add/update/delete bookkeeping is incomplete

- [ ] **Step 3: Implement informer handlers and pod-to-identity translation**

```go
func (p *KubernetesProvider) onAdd(obj interface{}) { ... }
func (p *KubernetesProvider) onUpdate(oldObj, newObj interface{}) { ... }
func (p *KubernetesProvider) onDelete(obj interface{}) { ... }

func buildIdentity(providerName string, pod *corev1.Pod) *Identity {
    return &Identity{
        Source:   "kubernetes",
        Provider: providerName,
        Name:     pod.Namespace + "/" + pod.Name,
        Labels:   labelsWithNamespace(pod.Namespace, pod.Labels),
    }
}
```

Handle nil/empty pod IPs safely, remove stale mappings when the IP changes, and inject `kubernetes.io/namespace` into labels.

- [ ] **Step 4: Run identity tests to verify they pass**

Run: `GOCACHE=$(pwd)/.cache/go-build GOMODCACHE=$(pwd)/.cache/mod go test ./internal/identity -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/identity/kubernetes.go internal/identity/kubernetes_test.go
git commit -m "feat: implement kubernetes pod identity tracking"
```

### Task 4: Full verification for the slice

**Files:**
- No new file targets; verification only

- [ ] **Step 1: Run the full repository test suite**

Run: `GOCACHE=$(pwd)/.cache/go-build GOMODCACHE=$(pwd)/.cache/mod go test ./...`
Expected: PASS

- [ ] **Step 2: Run the full repository build**

Run: `GOCACHE=$(pwd)/.cache/go-build GOMODCACHE=$(pwd)/.cache/mod go build ./...`
Expected: PASS

- [ ] **Step 3: Verify container build still succeeds**

Run: `docker build -t aegis:dev .`
Expected: PASS

- [ ] **Step 4: Commit any final test-only adjustments if needed**

```bash
git status --short
```

Expected: clean working tree

### Task 5: Publish updated branch state

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
