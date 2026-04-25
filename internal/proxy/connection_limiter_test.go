package proxy

import (
	"io"
	"log/slog"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/moolen/aegis/internal/identity"
	"github.com/moolen/aegis/internal/metrics"
)

func TestConnectionLimiterEnforcesCombinedPerIdentityLimit(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	limiter := NewConnectionLimiter(slog.New(slog.NewTextHandler(io.Discard, nil)), m)
	limiter.UpdateLimit(1)

	release, err := limiter.Acquire(&identity.Identity{Name: "default/web"}, "http")
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	defer release()

	if _, err := limiter.Acquire(&identity.Identity{Name: "default/web"}, "connect"); err == nil {
		t.Fatal("expected second acquire to fail")
	}
	if got := gaugeValue(t, reg, "aegis_identity_connections_active", map[string]string{"protocol": "http"}); got != 1 {
		t.Fatalf("http active gauge = %v, want 1", got)
	}
	if got := counterValue(t, reg, "aegis_identity_connection_limit_rejections_total", map[string]string{"protocol": "connect"}); got != 1 {
		t.Fatalf("connect rejection counter = %v, want 1", got)
	}
}

func TestConnectionLimiterUpdateLimitAppliesWithoutResettingActiveCounts(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	limiter := NewConnectionLimiter(slog.New(slog.NewTextHandler(io.Discard, nil)), m)
	limiter.UpdateLimit(1)

	releaseA, err := limiter.Acquire(&identity.Identity{Name: "default/web"}, "http")
	if err != nil {
		t.Fatalf("Acquire() first error = %v", err)
	}
	defer releaseA()

	if _, err := limiter.Acquire(&identity.Identity{Name: "default/web"}, "http"); err == nil {
		t.Fatal("expected acquire to fail at limit 1")
	}

	limiter.UpdateLimit(2)

	releaseB, err := limiter.Acquire(&identity.Identity{Name: "default/web"}, "connect")
	if err != nil {
		t.Fatalf("Acquire() after limit update error = %v", err)
	}
	releaseB()
	releaseA()

	if got := gaugeValue(t, reg, "aegis_identity_connection_limit"); got != 2 {
		t.Fatalf("limit gauge = %v, want 2", got)
	}
	if got := gaugeValue(t, reg, "aegis_identity_connections_active", map[string]string{"protocol": "http"}); got != 0 {
		t.Fatalf("http active gauge after release = %v, want 0", got)
	}
	if got := gaugeValue(t, reg, "aegis_identity_connections_active", map[string]string{"protocol": "connect"}); got != 0 {
		t.Fatalf("connect active gauge after release = %v, want 0", got)
	}
}

func gaugeValue(t *testing.T, reg *prometheus.Registry, name string, labels ...map[string]string) float64 {
	t.Helper()

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v", err)
	}

	wantLabels := map[string]string{}
	if len(labels) > 0 && labels[0] != nil {
		wantLabels = labels[0]
	}

	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.GetMetric() {
			if hasGaugeLabels(metric, wantLabels) {
				if metric.Gauge == nil {
					t.Fatalf("metric %q is not a gauge", name)
				}
				return metric.Gauge.GetValue()
			}
		}
	}

	t.Fatalf("metric %q with labels %#v not found", name, wantLabels)
	return 0
}

func hasGaugeLabels(metric *dto.Metric, want map[string]string) bool {
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
