package identity

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
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

func TestCompositeResolverRebindsWinnerIdentityToAuthoritativeProviderAndKind(t *testing.T) {
	resolver := NewCompositeResolver([]ProviderHandle{{
		Name: "production-ec2",
		Kind: "ec2",
		Resolver: stubResolver{identity: &Identity{
			Source:   "kubernetes",
			Provider: "stale-provider",
			Name:     "i-abc123",
		}},
	}}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)

	id, err := resolver.Resolve(net.ParseIP("10.0.0.20"))
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if id == nil {
		t.Fatal("Resolve() returned nil identity")
	}
	if id.Provider != "production-ec2" {
		t.Fatalf("provider = %q, want production-ec2", id.Provider)
	}
	if id.Source != "ec2" {
		t.Fatalf("source = %q, want ec2", id.Source)
	}
}

func TestCompositeResolverReadinessFailsWhenAllProvidersAreStaleOrDown(t *testing.T) {
	resolver := NewCompositeResolver([]ProviderHandle{
		{
			Name:     "cluster-a",
			Kind:     "kubernetes",
			Resolver: statusStubResolver{status: ProviderStatus{Name: "cluster-a", Kind: "kubernetes", State: ProviderStateStale}},
		},
		{
			Name:     "production-ec2",
			Kind:     "ec2",
			Resolver: statusStubResolver{status: ProviderStatus{Name: "production-ec2", Kind: "ec2", State: ProviderStateDown}},
		},
	}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)

	err := resolver.CheckReadiness()
	if err == nil {
		t.Fatal("expected readiness failure")
	}
	if !strings.Contains(err.Error(), "no active discovery providers") {
		t.Fatalf("readiness error = %q, want no active discovery providers", err)
	}
}

func TestCompositeResolverReadinessPassesWhenOneProviderIsActive(t *testing.T) {
	resolver := NewCompositeResolver([]ProviderHandle{
		{
			Name:     "cluster-a",
			Kind:     "kubernetes",
			Resolver: statusStubResolver{status: ProviderStatus{Name: "cluster-a", Kind: "kubernetes", State: ProviderStateStale}},
		},
		{
			Name:     "production-ec2",
			Kind:     "ec2",
			Resolver: statusStubResolver{status: ProviderStatus{Name: "production-ec2", Kind: "ec2", State: ProviderStateActive}},
		},
	}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)

	if err := resolver.CheckReadiness(); err != nil {
		t.Fatalf("CheckReadiness() error = %v", err)
	}
}

func TestCompositeResolverIdentityDumpRebindsNestedIdentityMetadata(t *testing.T) {
	resolver := NewCompositeResolver([]ProviderHandle{
		{
			Name: "cluster-a",
			Kind: "kubernetes",
			Resolver: snapshotStubResolver{entries: []Mapping{{
				IP:       "10.0.0.10",
				Provider: "stale-provider",
				Kind:     "ec2",
				Identity: &Identity{
					Source:   "ec2",
					Provider: "stale-provider",
					Name:     "default/api",
				},
			}}},
		},
		{
			Name: "production-ec2",
			Kind: "ec2",
			Resolver: snapshotStubResolver{entries: []Mapping{{
				IP:       "10.0.0.10",
				Provider: "other-stale-provider",
				Kind:     "kubernetes",
				Identity: &Identity{
					Source:   "kubernetes",
					Provider: "other-stale-provider",
					Name:     "i-shadow",
				},
			}}},
		},
	}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)

	entries := resolver.IdentityDump()
	if len(entries) != 1 {
		t.Fatalf("IdentityDump() = %#v, want one entry", entries)
	}
	if entries[0].Effective == nil || entries[0].Effective.Identity == nil {
		t.Fatalf("effective entry = %#v, want nested identity", entries[0].Effective)
	}
	if entries[0].Effective.Provider != "cluster-a" || entries[0].Effective.Kind != "kubernetes" {
		t.Fatalf("effective mapping = %#v, want authoritative provider/kind", entries[0].Effective)
	}
	if entries[0].Effective.Identity.Provider != "cluster-a" || entries[0].Effective.Identity.Source != "kubernetes" {
		t.Fatalf("effective identity = %#v, want authoritative provider/source", entries[0].Effective.Identity)
	}
	if len(entries[0].Shadows) != 1 {
		t.Fatalf("shadows = %#v, want one shadow", entries[0].Shadows)
	}
	if entries[0].Shadows[0].Identity == nil {
		t.Fatalf("shadow entry = %#v, want nested identity", entries[0].Shadows[0])
	}
	if entries[0].Shadows[0].Identity.Provider != "production-ec2" || entries[0].Shadows[0].Identity.Source != "ec2" {
		t.Fatalf("shadow identity = %#v, want authoritative provider/source", entries[0].Shadows[0].Identity)
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

type statusStubResolver struct {
	status ProviderStatus
}

func (r statusStubResolver) Resolve(net.IP) (*Identity, error) {
	return nil, nil
}

func (r statusStubResolver) ProviderStatus() ProviderStatus {
	return r.status
}

type snapshotStubResolver struct {
	entries []Mapping
}

func (r snapshotStubResolver) Resolve(net.IP) (*Identity, error) {
	return nil, nil
}

func (r snapshotStubResolver) IdentityMappings() []Mapping {
	out := make([]Mapping, 0, len(r.entries))
	for _, entry := range r.entries {
		out = append(out, Mapping{
			IP:       entry.IP,
			Provider: entry.Provider,
			Kind:     entry.Kind,
			Identity: cloneIdentity(entry.Identity),
		})
	}
	return out
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
