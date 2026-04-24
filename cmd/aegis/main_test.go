package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

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
	if got := counterValue(t, reg, "aegis_discovery_provider_failures_total", map[string]string{"provider": "broken-a", "kind": "kubernetes", "stage": "build"}); got != 1 {
		t.Fatalf("build failure metric = %v, want 1", got)
	}
	if got := gaugeValue(t, reg, "aegis_discovery_providers_active"); got != 1 {
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
