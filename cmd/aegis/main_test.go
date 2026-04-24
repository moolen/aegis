package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/moolen/aegis/internal/config"
	"github.com/moolen/aegis/internal/identity"
	appmetrics "github.com/moolen/aegis/internal/metrics"
	"github.com/moolen/aegis/internal/proxy"
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
	if got := counterValue(t, reg, "aegis_discovery_provider_failures_total", map[string]string{"provider": "broken-a", "kind": "kubernetes", "stage": "build"}); got != 1 {
		t.Fatalf("build failure metric = %v, want 1", got)
	}
	if metricExists(reg, "aegis_discovery_provider_starts_total", map[string]string{"provider": "broken-a", "kind": "kubernetes"}) {
		t.Fatal("broken-a build failure unexpectedly counted as a provider start")
	}
	if got := counterValue(t, reg, "aegis_discovery_provider_starts_total", map[string]string{"provider": "cluster-b", "kind": "kubernetes"}); got != 1 {
		t.Fatalf("start counter = %v, want 1", got)
	}
	if got := gaugeValue(t, reg, "aegis_discovery_providers_active"); got != 1 {
		t.Fatalf("active provider gauge = %v, want 1", got)
	}
}

func TestBuildIdentityResolverKeepsHealthyProvidersAfterStartupTimeout(t *testing.T) {
	restoreProvider := newKubernetesRuntimeProvider
	restoreTimeout := discoveryProviderStartupTimeout
	t.Cleanup(func() {
		newKubernetesRuntimeProvider = restoreProvider
		discoveryProviderStartupTimeout = restoreTimeout
	})

	discoveryProviderStartupTimeout = 20 * time.Millisecond

	newKubernetesRuntimeProvider = func(cfg config.KubernetesDiscoveryConfig, logger *slog.Logger) (identity.RuntimeProvider, error) {
		switch cfg.Name {
		case "stuck-a":
			return identity.RuntimeProvider{
				Name: "stuck-a",
				Kind: "kubernetes",
				Provider: fakeStartableResolver{
					startFn: func(ctx context.Context, startupTimeout time.Duration) error {
						select {
						case <-ctx.Done():
							return ctx.Err()
						case <-time.After(startupTimeout):
							return context.DeadlineExceeded
						}
					},
				},
			}, nil
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

	start := time.Now()
	resolver, err := buildIdentityResolver(context.Background(), config.DiscoveryConfig{
		Kubernetes: []config.KubernetesDiscoveryConfig{
			{Name: "stuck-a"},
			{Name: "cluster-b"},
		},
	}, slog.New(slog.NewTextHandler(io.Discard, nil)), m)
	if err != nil {
		t.Fatalf("buildIdentityResolver() error = %v", err)
	}
	if elapsed := time.Since(start); elapsed > 250*time.Millisecond {
		t.Fatalf("buildIdentityResolver() took %s, want timeout-bounded startup", elapsed)
	}

	id, err := resolver.Resolve(net.ParseIP("10.0.0.10"))
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if id == nil || id.Name != "ns-b/api" {
		t.Fatalf("Resolve() identity = %#v, want ns-b/api", id)
	}
	if got := counterValue(t, reg, "aegis_discovery_provider_failures_total", map[string]string{"provider": "stuck-a", "kind": "kubernetes", "stage": "start"}); got != 1 {
		t.Fatalf("start failure metric = %v, want 1", got)
	}
	if got := counterValue(t, reg, "aegis_discovery_provider_starts_total", map[string]string{"provider": "stuck-a", "kind": "kubernetes"}); got != 1 {
		t.Fatalf("start counter = %v, want 1", got)
	}
	if got := counterValue(t, reg, "aegis_discovery_provider_starts_total", map[string]string{"provider": "cluster-b", "kind": "kubernetes"}); got != 1 {
		t.Fatalf("healthy provider start counter = %v, want 1", got)
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
			Name:     "cluster-b",
			Kind:     "kubernetes",
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
	if got := counterValue(t, reg, "aegis_discovery_provider_failures_total", map[string]string{"provider": "cluster-b", "kind": "kubernetes", "stage": "start"}); got != 1 {
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

func TestBuildServersInjectsIdentityResolverIntoProxy(t *testing.T) {
	restoreProvider := newKubernetesRuntimeProvider
	restoreProxyServer := newProxyServer
	t.Cleanup(func() {
		newKubernetesRuntimeProvider = restoreProvider
		newProxyServer = restoreProxyServer
	})

	newKubernetesRuntimeProvider = func(cfg config.KubernetesDiscoveryConfig, logger *slog.Logger) (identity.RuntimeProvider, error) {
		if cfg.Name != "cluster-a" {
			t.Fatalf("unexpected provider %q", cfg.Name)
		}
		return identity.RuntimeProvider{
			Name: "cluster-a",
			Kind: "kubernetes",
			Provider: fakeStartableResolver{
				identity: &identity.Identity{Name: "default/api"},
			},
		}, nil
	}

	var captured proxy.Dependencies
	newProxyServer = func(deps proxy.Dependencies) interface{ Handler() http.Handler } {
		captured = deps
		return fakeHandlerProvider{handler: http.NewServeMux()}
	}

	_, _, err := buildServers(context.Background(), config.Config{
		Proxy:   config.ProxyConfig{Listen: ":8080"},
		Metrics: config.MetricsConfig{Listen: ":9090"},
		Policies: []config.PolicyConfig{{
			Name: "allow-example",
			Egress: []config.EgressRuleConfig{{
				FQDN:  "example.com",
				Ports: []int{443},
				TLS:   config.TLSRuleConfig{Mode: "passthrough"},
			}},
		}},
		Discovery: config.DiscoveryConfig{
			Kubernetes: []config.KubernetesDiscoveryConfig{{Name: "cluster-a"}},
		},
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("buildServers() error = %v", err)
	}
	if captured.IdentityResolver == nil {
		t.Fatal("IdentityResolver was not injected into proxy dependencies")
	}

	id, err := captured.IdentityResolver.Resolve(net.ParseIP("10.0.0.10"))
	if err != nil {
		t.Fatalf("IdentityResolver.Resolve() error = %v", err)
	}
	if id == nil || id.Name != "default/api" {
		t.Fatalf("IdentityResolver.Resolve() identity = %#v, want default/api", id)
	}
}

type fakeStartableResolver struct {
	identity *identity.Identity
	startErr error
	startFn  func(context.Context, time.Duration) error
}

func (r fakeStartableResolver) Start(ctx context.Context, startupTimeout time.Duration) error {
	if r.startFn != nil {
		return r.startFn(ctx, startupTimeout)
	}
	return r.startErr
}

func (r fakeStartableResolver) Resolve(net.IP) (*identity.Identity, error) {
	return r.identity, nil
}

type fakeHandlerProvider struct {
	handler http.Handler
}

func (p fakeHandlerProvider) Handler() http.Handler {
	return p.handler
}

func counterValue(t *testing.T, reg *prometheus.Registry, name string, labels map[string]string) float64 {
	t.Helper()

	metric := mustFindMetric(t, reg, name, labels)
	if metric.Counter == nil {
		t.Fatalf("metric %q is not a counter", name)
	}

	return metric.Counter.GetValue()
}

func gaugeValue(t *testing.T, reg *prometheus.Registry, name string) float64 {
	t.Helper()

	metric := mustFindMetric(t, reg, name, nil)
	if metric.Gauge == nil {
		t.Fatalf("metric %q is not a gauge", name)
	}

	return metric.Gauge.GetValue()
}

func mustFindMetric(t *testing.T, reg *prometheus.Registry, name string, labels map[string]string) *dto.Metric {
	t.Helper()

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v", err)
	}

	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.GetMetric() {
			if hasLabels(metric, labels) {
				return metric
			}
		}
	}

	t.Fatalf("metric %q with labels %#v not found", name, labels)
	return nil
}

func metricExists(reg *prometheus.Registry, name string, labels map[string]string) bool {
	families, err := reg.Gather()
	if err != nil {
		return false
	}

	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.GetMetric() {
			if hasLabels(metric, labels) {
				return true
			}
		}
	}

	return false
}

func hasLabels(metric *dto.Metric, want map[string]string) bool {
	if len(want) == 0 {
		return len(metric.GetLabel()) == 0
	}
	if len(metric.GetLabel()) != len(want) {
		return false
	}

	for _, pair := range metric.GetLabel() {
		if want[pair.GetName()] != pair.GetValue() {
			return false
		}
	}

	return true
}
