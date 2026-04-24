package identity

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

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
	if got := counterValue(t, m.IdentityOverlapsTotal.WithLabelValues("cluster-a", "kubernetes", "cluster-b", "kubernetes")); got != 1 {
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
	if got := counterValue(t, m.IdentityResolutionsTotal.WithLabelValues("broken-a", "kubernetes", "error")); got != 1 {
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
	if got := counterValue(t, m.IdentityResolutionsTotal.WithLabelValues("cluster-b", "kubernetes", "miss")); got != 1 {
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
	if got := counterValue(t, m.IdentityResolutionsTotal.WithLabelValues("broken-a", "kubernetes", "error")); got != 1 {
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

func counterValue(t *testing.T, collector prometheus.Collector) float64 {
	t.Helper()

	metric := &dto.Metric{}
	if err := collector.(prometheus.Metric).Write(metric); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if metric.Counter == nil {
		t.Fatalf("metric counter = nil")
	}

	return metric.Counter.GetValue()
}
