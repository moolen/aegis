package identity

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

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
	if got := gatheredCounterValue(t, reg, "aegis_identity_overlaps_total", map[string]string{
		"winner_provider": "cluster-a",
		"winner_kind":     "kubernetes",
		"shadow_provider": "cluster-b",
		"shadow_kind":     "kubernetes",
	}); got != 1 {
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
	if got := gatheredCounterValue(t, reg, "aegis_identity_resolutions_total", map[string]string{
		"provider": "broken-a",
		"kind":     "kubernetes",
		"result":   "error",
	}); got != 1 {
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
	if got := gatheredCounterValue(t, reg, "aegis_identity_resolutions_total", map[string]string{
		"provider": "cluster-b",
		"kind":     "kubernetes",
		"result":   "miss",
	}); got != 1 {
		t.Fatalf("miss metric = %v, want 1", got)
	}
}

func TestCompositeResolverContinuesAfterNilProviderResolver(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := appmetrics.New(reg)
	resolver := NewCompositeResolver([]ProviderHandle{
		{Name: "broken-a", Kind: "kubernetes"},
		{
			Name:     "cluster-b",
			Kind:     "kubernetes",
			Resolver: stubResolver{identity: &Identity{Name: "ns-b/api"}},
		},
	}, slog.New(slog.NewTextHandler(io.Discard, nil)), m)

	id, err := resolver.Resolve(net.ParseIP("10.0.0.13"))
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if id == nil || id.Name != "ns-b/api" {
		t.Fatalf("Resolve() identity = %#v, want ns-b/api", id)
	}
	if got := gatheredCounterValue(t, reg, "aegis_identity_resolutions_total", map[string]string{
		"provider": "broken-a",
		"kind":     "kubernetes",
		"result":   "error",
	}); got != 1 {
		t.Fatalf("error metric = %v, want 1", got)
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

func gatheredCounterValue(t *testing.T, reg *prometheus.Registry, metricName string, labels map[string]string) float64 {
	t.Helper()

	metricFamilies, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v", err)
	}

	for _, family := range metricFamilies {
		if family.GetName() != metricName {
			continue
		}
		for _, metric := range family.GetMetric() {
			pairs := metric.GetLabel()
			if len(pairs) != len(labels) {
				continue
			}

			matched := true
			for _, pair := range pairs {
				if labels[pair.GetName()] != pair.GetValue() {
					matched = false
					break
				}
			}

			if !matched {
				continue
			}

			if metric.GetCounter() == nil {
				t.Fatalf("metric counter = nil for %s", metricName)
			}
			return metric.GetCounter().GetValue()
		}
		t.Fatalf("metric %s with labels %v not found", metricName, labels)
	}

	t.Fatalf("metric family %s not found", metricName)
	return 0
}
