# Aegis Runtime Discovery Wiring Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire multiple configured discovery providers into the shipped Aegis runtime so plain HTTP policy enforcement can use real workload identities, while tolerating partial provider startup failure and exposing discovery behavior through metrics and logs.

**Architecture:** This slice adds discovery-specific metrics, introduces an ordered composite identity resolver in `internal/identity`, adds runtime Kubernetes provider construction helpers that hide Kubernetes client creation from `cmd/aegis`, and refactors startup wiring to build/start providers, keep healthy ones, and inject the composite resolver into the proxy. Provider precedence is config order, the first match wins, later overlaps are logged and counted, and startup only fails when discovery is configured but zero providers become active.

**Tech Stack:** Go 1.26, `slog`, Prometheus client_golang, `client-go` cache/rest/clientcmd packages, YAML v3.

---

### Task 1: Add discovery metrics and an ordered composite resolver

**Files:**
- Modify: `internal/metrics/metrics.go`
- Create: `internal/identity/composite.go`
- Create: `internal/identity/composite_test.go`

- [ ] **Step 1: Write failing composite-resolver tests**

```go
package identity

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	appmetrics "github.com/moolen/aegis/internal/metrics"
)

func TestCompositeResolverReturnsFirstMatchingProvider(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := appmetrics.New(reg)
	resolver := NewCompositeResolver([]ProviderHandle{
		{
			Name:     "cluster-a",
			Kind:     "kubernetes",
			Resolver: stubResolver{identity: &Identity{Name: "ns-a/web", Labels: map[string]string{"app": "web"}}},
		},
		{
			Name:     "cluster-b",
			Kind:     "kubernetes",
			Resolver: stubResolver{identity: &Identity{Name: "ns-b/web", Labels: map[string]string{"app": "shadow"}}},
		},
	}, slog.New(slog.NewTextHandler(io.Discard, nil)), m)

	id, err := resolver.Resolve(net.ParseIP("10.0.0.10"))
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if id == nil || id.Name != "ns-a/web" {
		t.Fatalf("Resolve() identity = %#v, want ns-a/web", id)
	}
	if got := testutil.ToFloat64(m.IdentityOverlapsTotal.WithLabelValues("cluster-a", "kubernetes", "cluster-b", "kubernetes")); got != 1 {
		t.Fatalf("overlap metric = %v, want 1", got)
	}
}

func TestCompositeResolverContinuesAfterProviderError(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := appmetrics.New(reg)
	resolver := NewCompositeResolver([]ProviderHandle{
		{
			Name:     "broken-a",
			Kind:     "kubernetes",
			Resolver: stubResolver{err: errors.New("boom")},
		},
		{
			Name:     "cluster-b",
			Kind:     "kubernetes",
			Resolver: stubResolver{identity: &Identity{Name: "ns-b/api"}},
		},
	}, slog.New(slog.NewTextHandler(io.Discard, nil)), m)

	id, err := resolver.Resolve(net.ParseIP("10.0.0.11"))
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if id == nil || id.Name != "ns-b/api" {
		t.Fatalf("Resolve() identity = %#v, want ns-b/api", id)
	}
	if got := testutil.ToFloat64(m.IdentityResolutionsTotal.WithLabelValues("broken-a", "kubernetes", "error")); got != 1 {
		t.Fatalf("error metric = %v, want 1", got)
	}
}

func TestCompositeResolverReturnsNilWhenAllProvidersMiss(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := appmetrics.New(reg)
	resolver := NewCompositeResolver([]ProviderHandle{
		{Name: "cluster-a", Kind: "kubernetes", Resolver: stubResolver{}},
		{Name: "cluster-b", Kind: "kubernetes", Resolver: stubResolver{}},
	}, slog.New(slog.NewTextHandler(io.Discard, nil)), m)

	id, err := resolver.Resolve(net.ParseIP("10.0.0.12"))
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if id != nil {
		t.Fatalf("Resolve() identity = %#v, want nil", id)
	}
	if got := testutil.ToFloat64(m.IdentityResolutionsTotal.WithLabelValues("cluster-b", "kubernetes", "miss")); got != 1 {
		t.Fatalf("miss metric = %v, want 1", got)
	}
}

type stubResolver struct {
	identity *Identity
	err      error
}

func (r stubResolver) Resolve(net.IP) (*Identity, error) {
	if r.err != nil {
		return nil, r.err
	}
	return r.identity, nil
}
```

- [ ] **Step 2: Run the new identity tests to verify they fail**

Run: `mkdir -p .cache/tmp .cache/go-build .cache/mod && GOCACHE=$(pwd)/.cache/go-build GOTMPDIR=$(pwd)/.cache/tmp GOMODCACHE=$(pwd)/.cache/mod go test ./internal/identity -run 'TestCompositeResolver(ReturnsFirstMatchingProvider|ContinuesAfterProviderError|ReturnsNilWhenAllProvidersMiss)' -v`
Expected: FAIL because `ProviderHandle`, `NewCompositeResolver`, and the new metrics do not exist yet

- [ ] **Step 3: Implement discovery metrics and the composite resolver**

```go
type Metrics struct {
	RequestsTotal                  *prometheus.CounterVec
	ErrorsTotal                    *prometheus.CounterVec
	RequestDuration                *prometheus.HistogramVec
	DNSResolutionsTotal            *prometheus.CounterVec
	DNSDuration                    prometheus.Histogram
	DiscoveryProviderStartsTotal   *prometheus.CounterVec
	DiscoveryProviderFailuresTotal *prometheus.CounterVec
	DiscoveryProvidersActive       prometheus.Gauge
	IdentityResolutionsTotal       *prometheus.CounterVec
	IdentityOverlapsTotal          *prometheus.CounterVec
}

type ProviderHandle struct {
	Name     string
	Kind     string
	Resolver Resolver
}

type CompositeResolver struct {
	providers []ProviderHandle
	logger    *slog.Logger
	metrics   *metrics.Metrics
}

func NewCompositeResolver(providers []ProviderHandle, logger *slog.Logger, m *metrics.Metrics) *CompositeResolver {
	if logger == nil {
		logger = slog.Default()
	}
	return &CompositeResolver{providers: providers, logger: logger, metrics: m}
}

func (r *CompositeResolver) Resolve(ip net.IP) (*Identity, error) {
	var winner *Identity
	var winnerProvider ProviderHandle

	for _, provider := range r.providers {
		id, err := provider.Resolver.Resolve(ip)
		if err != nil {
			r.logger.Warn("identity resolve failed", "provider", provider.Name, "kind", provider.Kind, "ip", ip.String(), "error", err)
			if r.metrics != nil {
				r.metrics.IdentityResolutionsTotal.WithLabelValues(provider.Name, provider.Kind, "error").Inc()
			}
			continue
		}
		if id == nil {
			if r.metrics != nil {
				r.metrics.IdentityResolutionsTotal.WithLabelValues(provider.Name, provider.Kind, "miss").Inc()
			}
			continue
		}
		if r.metrics != nil {
			r.metrics.IdentityResolutionsTotal.WithLabelValues(provider.Name, provider.Kind, "hit").Inc()
		}
		if winner == nil {
			winner = id
			winnerProvider = provider
			continue
		}
		r.logger.Warn("identity overlap detected", "ip", ip.String(), "winner_provider", winnerProvider.Name, "winner_kind", winnerProvider.Kind, "shadow_provider", provider.Name, "shadow_kind", provider.Kind)
		if r.metrics != nil {
			r.metrics.IdentityOverlapsTotal.WithLabelValues(winnerProvider.Name, winnerProvider.Kind, provider.Name, provider.Kind).Inc()
		}
	}

	return winner, nil
}
```

Register the new collectors in `internal/metrics/metrics.go` with labels:

- `aegis_discovery_provider_starts_total{provider,kind}`
- `aegis_discovery_provider_failures_total{provider,kind,stage}`
- `aegis_discovery_providers_active`
- `aegis_identity_resolutions_total{provider,kind,result}`
- `aegis_identity_overlaps_total{winner_provider,winner_kind,shadow_provider,shadow_kind}`

- [ ] **Step 4: Run focused identity tests to verify they pass**

Run: `mkdir -p .cache/tmp .cache/go-build .cache/mod && GOCACHE=$(pwd)/.cache/go-build GOTMPDIR=$(pwd)/.cache/tmp GOMODCACHE=$(pwd)/.cache/mod go test ./internal/identity -run 'TestCompositeResolver(ReturnsFirstMatchingProvider|ContinuesAfterProviderError|ReturnsNilWhenAllProvidersMiss)' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/metrics/metrics.go internal/identity/composite.go internal/identity/composite_test.go
git commit -m "feat: add composite identity resolver"
```

### Task 2: Add runtime Kubernetes provider construction helpers

**Files:**
- Create: `internal/identity/runtime.go`
- Create: `internal/identity/runtime_test.go`

- [ ] **Step 1: Write failing tests for Kubernetes runtime construction**

```go
package identity

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/rest"

	"github.com/moolen/aegis/internal/config"
)

func TestNewKubernetesRuntimeProviderUsesExplicitKubeconfig(t *testing.T) {
	restoreLoad := loadRESTConfig
	restoreSource := newKubernetesPodSource
	t.Cleanup(func() {
		loadRESTConfig = restoreLoad
		newKubernetesPodSource = restoreSource
	})

	var loadedPath string
	loadRESTConfig = func(kubeconfig string) (any, error) {
		loadedPath = kubeconfig
		return struct{}{}, nil
	}
	newKubernetesPodSource = func(any) (KubernetesPodSource, error) {
		return fakeRuntimePodSource{}, nil
	}

	handle, err := NewKubernetesRuntimeProvider(config.KubernetesDiscoveryConfig{
		Name:         "cluster-a",
		Kubeconfig:   "/tmp/a.kubeconfig",
		Namespaces:   []string{"default"},
		ResyncPeriod: func() *time.Duration { d := 15 * time.Second; return &d }(),
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewKubernetesRuntimeProvider() error = %v", err)
	}
	if loadedPath != "/tmp/a.kubeconfig" {
		t.Fatalf("loaded kubeconfig = %q, want /tmp/a.kubeconfig", loadedPath)
	}
	if handle.Name != "cluster-a" || handle.Kind != "kubernetes" {
		t.Fatalf("handle = %#v, want kubernetes/cluster-a", handle)
	}
}

func TestNewKubernetesRuntimeProviderFallsBackToInClusterConfig(t *testing.T) {
	restoreLoad := loadRESTConfig
	restoreSource := newKubernetesPodSource
	t.Cleanup(func() {
		loadRESTConfig = restoreLoad
		newKubernetesPodSource = restoreSource
	})

	loadRESTConfig = func(kubeconfig string) (any, error) {
		if kubeconfig != "" {
			t.Fatalf("loadRESTConfig kubeconfig = %q, want empty", kubeconfig)
		}
		return struct{}{}, nil
	}
	newKubernetesPodSource = func(any) (KubernetesPodSource, error) {
		return fakeRuntimePodSource{}, nil
	}

	_, err := NewKubernetesRuntimeProvider(config.KubernetesDiscoveryConfig{Name: "cluster-a"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewKubernetesRuntimeProvider() error = %v", err)
	}
}

func TestNewKubernetesRuntimeProviderPropagatesSourceErrors(t *testing.T) {
	restoreLoad := loadRESTConfig
	restoreSource := newKubernetesPodSource
	t.Cleanup(func() {
		loadRESTConfig = restoreLoad
		newKubernetesPodSource = restoreSource
	})

	loadRESTConfig = func(string) (any, error) {
		return struct{}{}, nil
	}
	newKubernetesPodSource = func(any) (KubernetesPodSource, error) {
		return nil, errors.New("no cluster")
	}

	_, err := NewKubernetesRuntimeProvider(config.KubernetesDiscoveryConfig{Name: "cluster-a"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err == nil {
		t.Fatal("expected construction error")
	}
}

type fakeRuntimePodSource struct{}

func (fakeRuntimePodSource) Pods(string) KubernetesPodNamespaceClient {
	return fakeRuntimeNamespaceClient{}
}

type fakeRuntimeNamespaceClient struct{}

func (fakeRuntimeNamespaceClient) List(context.Context, metav1.ListOptions) (*corev1.PodList, error) {
	return &corev1.PodList{}, nil
}

func (fakeRuntimeNamespaceClient) Watch(context.Context, metav1.ListOptions) (watch.Interface, error) {
	return watch.NewRaceFreeFake(), nil
}
```

- [ ] **Step 2: Run the runtime-construction tests to verify they fail**

Run: `mkdir -p .cache/tmp .cache/go-build .cache/mod && GOCACHE=$(pwd)/.cache/go-build GOTMPDIR=$(pwd)/.cache/tmp GOMODCACHE=$(pwd)/.cache/mod go test ./internal/identity -run 'TestNewKubernetesRuntimeProvider(UsesExplicitKubeconfig|FallsBackToInClusterConfig|PropagatesSourceErrors)' -v`
Expected: FAIL because `NewKubernetesRuntimeProvider`, `loadRESTConfig`, and `newKubernetesPodSource` do not exist yet

- [ ] **Step 3: Implement Kubernetes runtime construction helpers**

```go
type StartableResolver interface {
	Start(context.Context) error
	Resolve(net.IP) (*Identity, error)
}

var loadRESTConfig = func(kubeconfig string) (*rest.Config, error) {
	if kubeconfig != "" {
		return clientcmd.BuildConfigFromFlags("", kubeconfig)
	}
	return rest.InClusterConfig()
}

var newKubernetesPodSource = func(restCfg *rest.Config) (KubernetesPodSource, error) {
	clientset, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return nil, err
	}
	return coreV1PodSource{client: clientset.CoreV1()}, nil
}

type RuntimeProvider struct {
	Name     string
	Kind     string
	Provider StartableResolver
}

func NewKubernetesRuntimeProvider(cfg config.KubernetesDiscoveryConfig, logger *slog.Logger) (RuntimeProvider, error) {
	restCfg, err := loadRESTConfig(cfg.Kubeconfig)
	if err != nil {
		return RuntimeProvider{}, fmt.Errorf("load kubernetes rest config for %s: %w", cfg.Name, err)
	}
	source, err := newKubernetesPodSource(restCfg)
	if err != nil {
		return RuntimeProvider{}, fmt.Errorf("build kubernetes pod source for %s: %w", cfg.Name, err)
	}

	resync := time.Minute
	if cfg.ResyncPeriod != nil {
		resync = *cfg.ResyncPeriod
	}

	provider, err := NewKubernetesProvider(KubernetesProviderConfig{
		Name:         cfg.Name,
		Source:       source,
		Namespaces:   cfg.Namespaces,
		ResyncPeriod: resync,
	}, logger)
	if err != nil {
		return RuntimeProvider{}, err
	}

	return RuntimeProvider{
		Name:     cfg.Name,
		Kind:     "kubernetes",
		Provider: provider,
	}, nil
}
```

Use a small `coreV1PodSource` adapter in the same file so `cmd/aegis` never needs Kubernetes client types.

- [ ] **Step 4: Run focused identity tests to verify they pass**

Run: `mkdir -p .cache/tmp .cache/go-build .cache/mod && GOCACHE=$(pwd)/.cache/go-build GOTMPDIR=$(pwd)/.cache/tmp GOMODCACHE=$(pwd)/.cache/mod go test ./internal/identity -run 'Test(NewKubernetesRuntimeProvider(UsesExplicitKubeconfig|FallsBackToInClusterConfig|PropagatesSourceErrors)|CompositeResolver(ReturnsFirstMatchingProvider|ContinuesAfterProviderError|ReturnsNilWhenAllProvidersMiss))' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/identity/runtime.go internal/identity/runtime_test.go
git commit -m "feat: add discovery runtime provider construction"
```

### Task 3: Refactor startup wiring to build, start, and compose providers

**Files:**
- Modify: `cmd/aegis/main.go`
- Create: `cmd/aegis/main_test.go`

- [ ] **Step 1: Write failing startup-orchestration tests**

```go
package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/moolen/aegis/internal/config"
	"github.com/moolen/aegis/internal/identity"
	appmetrics "github.com/moolen/aegis/internal/metrics"
)

func TestBuildIdentityResolverKeepsHealthyProvidersAfterStartupFailure(t *testing.T) {
	restore := newKubernetesRuntimeProvider
	t.Cleanup(func() { newKubernetesRuntimeProvider = restore })

	var attempts []string
	newKubernetesRuntimeProvider = func(cfg config.KubernetesDiscoveryConfig, logger *slog.Logger) (identity.RuntimeProvider, error) {
		attempts = append(attempts, cfg.Name)
		switch cfg.Name {
		case "broken-a":
			return identity.RuntimeProvider{}, errors.New("bad kubeconfig")
		case "cluster-b":
			return identity.RuntimeProvider{
				Name: "cluster-b",
				Kind: "kubernetes",
				Provider: fakeStartableResolver{
					identity: &identity.Identity{Name: "ns-b/api"},
				},
			}, nil
		default:
			t.Fatalf("unexpected provider %q", cfg.Name)
			return identity.RuntimeProvider{}, nil
		}
	}

	reg := prometheus.NewRegistry()
	m := appmetrics.New(reg)
	resolver, err := buildIdentityResolver(context.Background(), config.DiscoveryConfig{
		Kubernetes: []config.KubernetesDiscoveryConfig{
			{Name: "broken-a"},
			{Name: "cluster-b"},
		},
	}, slog.New(slog.NewTextHandler(io.Discard, nil)), m)
	if err != nil {
		t.Fatalf("buildIdentityResolver() error = %v", err)
	}
	if len(attempts) != 2 {
		t.Fatalf("attempts = %#v, want broken-a then cluster-b", attempts)
	}
	id, err := resolver.Resolve(net.ParseIP("10.0.0.10"))
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if id == nil || id.Name != "ns-b/api" {
		t.Fatalf("Resolve() identity = %#v, want ns-b/api", id)
	}
	if got := testutil.ToFloat64(m.DiscoveryProviderFailuresTotal.WithLabelValues("broken-a", "kubernetes", "build")); got != 1 {
		t.Fatalf("build failure metric = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.DiscoveryProvidersActive); got != 1 {
		t.Fatalf("active provider gauge = %v, want 1", got)
	}
}

func TestBuildIdentityResolverFailsWhenDiscoveryConfiguredButNoProviderIsHealthy(t *testing.T) {
	restore := newKubernetesRuntimeProvider
	t.Cleanup(func() { newKubernetesRuntimeProvider = restore })

	newKubernetesRuntimeProvider = func(cfg config.KubernetesDiscoveryConfig, logger *slog.Logger) (identity.RuntimeProvider, error) {
		if cfg.Name == "broken-a" {
			return identity.RuntimeProvider{}, errors.New("bad kubeconfig")
		}
		return identity.RuntimeProvider{
			Name: "cluster-b",
			Kind: "kubernetes",
			Provider: fakeStartableResolver{startErr: errors.New("sync failed")},
		}, nil
	}

	reg := prometheus.NewRegistry()
	m := appmetrics.New(reg)
	_, err := buildIdentityResolver(context.Background(), config.DiscoveryConfig{
		Kubernetes: []config.KubernetesDiscoveryConfig{
			{Name: "broken-a"},
			{Name: "cluster-b"},
		},
	}, slog.New(slog.NewTextHandler(io.Discard, nil)), m)
	if err == nil {
		t.Fatal("expected startup failure")
	}
	if got := testutil.ToFloat64(m.DiscoveryProviderFailuresTotal.WithLabelValues("cluster-b", "kubernetes", "start")); got != 1 {
		t.Fatalf("start failure metric = %v, want 1", got)
	}
}

func TestBuildIdentityResolverReturnsNilWhenDiscoveryDisabled(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := appmetrics.New(reg)
	resolver, err := buildIdentityResolver(context.Background(), config.DiscoveryConfig{}, slog.New(slog.NewTextHandler(io.Discard, nil)), m)
	if err != nil {
		t.Fatalf("buildIdentityResolver() error = %v", err)
	}
	if resolver != nil {
		t.Fatalf("resolver = %#v, want nil", resolver)
	}
}

type fakeStartableResolver struct {
	identity *identity.Identity
	startErr error
}

func (r fakeStartableResolver) Start(context.Context) error {
	return r.startErr
}

func (r fakeStartableResolver) Resolve(net.IP) (*identity.Identity, error) {
	return r.identity, nil
}
```

Add one assertion for:

- `aegis_discovery_provider_failures_total{provider="broken-a",kind="kubernetes",stage="build"} == 1`
- `aegis_discovery_providers_active == 1`

- [ ] **Step 2: Run the startup tests to verify they fail**

Run: `mkdir -p .cache/tmp .cache/go-build .cache/mod && GOCACHE=$(pwd)/.cache/go-build GOTMPDIR=$(pwd)/.cache/tmp GOMODCACHE=$(pwd)/.cache/mod go test ./cmd/aegis -run 'TestBuildIdentityResolver(KeepsHealthyProvidersAfterStartupFailure|FailsWhenDiscoveryConfiguredButNoProviderIsHealthy|ReturnsNilWhenDiscoveryDisabled)' -v`
Expected: FAIL because `buildIdentityResolver` and the injectable provider factory do not exist yet

- [ ] **Step 3: Refactor startup wiring and inject the composite resolver**

```go
var newKubernetesRuntimeProvider = func(cfg config.KubernetesDiscoveryConfig, logger *slog.Logger) (identity.RuntimeProvider, error) {
	return identity.NewKubernetesRuntimeProvider(cfg, logger)
}

func run() int {
	// existing config load and policy setup

	registry := prometheus.NewRegistry()
	m := appmetrics.New(registry)
	resolver := dns.NewResolver(dns.Config{
		CacheTTL: cfg.DNS.CacheTTL,
		Timeout:  cfg.DNS.Timeout,
		Servers:  cfg.DNS.Servers,
	}, nil, logger, m)

	identityResolver, err := buildIdentityResolver(context.Background(), cfg.Discovery, logger, m)
	if err != nil {
		logger.Error("build identity resolver failed", "error", err)
		return 1
	}

	proxyHandler := proxy.NewServer(proxy.Dependencies{
		Resolver:         resolver,
		IdentityResolver: identityResolver,
		PolicyEngine:     engine,
		Metrics:          m,
		Logger:           logger,
	})
}

func buildIdentityResolver(ctx context.Context, cfg config.DiscoveryConfig, logger *slog.Logger, m *appmetrics.Metrics) (proxy.IdentityResolver, error) {
	if len(cfg.Kubernetes) == 0 {
		return nil, nil
	}

	active := make([]identity.ProviderHandle, 0, len(cfg.Kubernetes))
	for _, kubeCfg := range cfg.Kubernetes {
		if m != nil {
			m.DiscoveryProviderStartsTotal.WithLabelValues(kubeCfg.Name, "kubernetes").Inc()
		}
		handle, err := newKubernetesRuntimeProvider(kubeCfg, logger)
		if err != nil {
			logger.Warn("discovery provider build failed", "provider", kubeCfg.Name, "kind", "kubernetes", "error", err)
			if m != nil {
				m.DiscoveryProviderFailuresTotal.WithLabelValues(kubeCfg.Name, "kubernetes", "build").Inc()
			}
			continue
		}
		if err := handle.Provider.Start(ctx); err != nil {
			logger.Warn("discovery provider start failed", "provider", handle.Name, "kind", handle.Kind, "error", err)
			if m != nil {
				m.DiscoveryProviderFailuresTotal.WithLabelValues(handle.Name, handle.Kind, "start").Inc()
			}
			continue
		}
		active = append(active, identity.ProviderHandle{Name: handle.Name, Kind: handle.Kind, Resolver: handle.Provider})
	}
	if len(cfg.Kubernetes) > 0 && len(active) == 0 {
		return nil, fmt.Errorf("discovery configured but no providers became active")
	}
	if m != nil {
		m.DiscoveryProvidersActive.Set(float64(len(active)))
	}
	if len(active) == 0 {
		return nil, nil
	}
	return identity.NewCompositeResolver(active, logger, m), nil
}
```

Keep the existing unknown-identity fallback by passing `nil` when discovery is not configured or no active providers are available because discovery was not configured in the first place.

- [ ] **Step 4: Run focused startup tests to verify they pass**

Run: `mkdir -p .cache/tmp .cache/go-build .cache/mod && GOCACHE=$(pwd)/.cache/go-build GOTMPDIR=$(pwd)/.cache/tmp GOMODCACHE=$(pwd)/.cache/mod go test ./cmd/aegis -run 'TestBuildIdentityResolver(KeepsHealthyProvidersAfterStartupFailure|FailsWhenDiscoveryConfiguredButNoProviderIsHealthy|ReturnsNilWhenDiscoveryDisabled)' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add cmd/aegis/main.go cmd/aegis/main_test.go
git commit -m "feat: wire discovery providers into runtime"
```

### Task 4: Update example config and runtime docs

**Files:**
- Modify: `aegis.example.yaml`
- Modify: `README.md`
- Modify: `deploy/helm/values.yaml`
- Modify: `internal/config/config_test.go`

- [ ] **Step 1: Write a failing documentation-oriented test for the example config**

```go
func TestExampleConfigIncludesDiscoverySection(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "aegis.example.yaml"))
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if !strings.Contains(string(data), "discovery:") {
		t.Fatal("example config does not mention discovery")
	}
}
```

Place this in `internal/config/config_test.go` so the example config remains coupled to the runtime config shape.

- [ ] **Step 2: Run the example-config test to verify it fails**

Run: `mkdir -p .cache/tmp .cache/go-build .cache/mod && GOCACHE=$(pwd)/.cache/go-build GOTMPDIR=$(pwd)/.cache/tmp GOMODCACHE=$(pwd)/.cache/mod go test ./internal/config -run 'TestExampleConfigIncludesDiscoverySection' -v`
Expected: FAIL because `aegis.example.yaml` does not mention discovery yet

- [ ] **Step 3: Update the example config and docs to match the shipped runtime**

```yaml
discovery:
  kubernetes:
    - name: cluster-a
      kubeconfig: ""
      namespaces: ["default"]
      resyncPeriod: 30s
```

Update `README.md`:

- remove the statement that runtime identity resolution is not wired yet,
- state that Kubernetes discovery is now runtime-wired,
- clarify that multiple providers are supported in config order,
- note that EC2 discovery and TLS inspection remain unimplemented,
- explain that provider startup failures are tolerated and exposed through metrics.

Update `deploy/helm/values.yaml` comments so they no longer claim identity discovery is unwired. Keep the default `identitySelector.matchLabels` empty, but explain that this is a safe starter policy, not a runtime limitation.

- [ ] **Step 4: Run the example-config test to verify it passes**

Run: `mkdir -p .cache/tmp .cache/go-build .cache/mod && GOCACHE=$(pwd)/.cache/go-build GOTMPDIR=$(pwd)/.cache/tmp GOMODCACHE=$(pwd)/.cache/mod go test ./internal/config -run 'TestExampleConfigIncludesDiscoverySection' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add aegis.example.yaml README.md deploy/helm/values.yaml internal/config/config_test.go
git commit -m "docs: update runtime discovery documentation"
```

### Task 5: Full verification and publish

**Files:**
- Modify: `.git/config`

- [ ] **Step 1: Run the full repository test suite**

Run: `mkdir -p .cache/tmp .cache/go-build .cache/mod && GOCACHE=$(pwd)/.cache/go-build GOTMPDIR=$(pwd)/.cache/tmp GOMODCACHE=$(pwd)/.cache/mod go test ./...`
Expected: PASS

- [ ] **Step 2: Run the full repository build**

Run: `mkdir -p .cache/tmp .cache/go-build .cache/mod && GOCACHE=$(pwd)/.cache/go-build GOTMPDIR=$(pwd)/.cache/tmp GOMODCACHE=$(pwd)/.cache/mod go build ./...`
Expected: PASS

- [ ] **Step 3: Verify the container build still succeeds**

Run: `docker build -t aegis:dev .`
Expected: PASS

- [ ] **Step 4: Verify the working tree is clean before push**

Run: `git status --short --branch`
Expected: clean working tree on `feat/mvp-bootstrap`

- [ ] **Step 5: Push the updated branch contents to remote `main`**

```bash
git push origin feat/mvp-bootstrap:main
```

- [ ] **Step 6: Verify the remote head moved**

Run: `git ls-remote --heads origin`
Expected: `refs/heads/main` points at the latest local commit
