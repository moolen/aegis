package proxy

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/moolen/aegis/internal/metrics"
)

func TestDrainTrackerTracksActiveTunnels(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	tracker := NewDrainTracker(slog.New(slog.NewTextHandler(io.Discard, nil)), m)

	release := tracker.Track("passthrough")
	if got := tracker.ActiveCount(); got != 1 {
		t.Fatalf("active count = %d, want 1", got)
	}
	if got := counterOrGaugeValue(t, reg, "aegis_connect_tunnels_active", map[string]string{"mode": "passthrough"}); got != 1 {
		t.Fatalf("active gauge = %v, want 1", got)
	}

	release()
	if got := tracker.ActiveCount(); got != 0 {
		t.Fatalf("active count = %d, want 0", got)
	}
	if got := counterOrGaugeValue(t, reg, "aegis_connect_tunnels_active", map[string]string{"mode": "passthrough"}); got != 0 {
		t.Fatalf("active gauge = %v, want 0", got)
	}
}

func TestDrainTrackerShutdownWaitsForCleanDrain(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	tracker := NewDrainTracker(slog.New(slog.NewTextHandler(io.Discard, nil)), m)

	release := tracker.Track("mitm")
	go func() {
		time.Sleep(20 * time.Millisecond)
		release()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	if got := tracker.Shutdown(ctx); got != "clean" {
		t.Fatalf("shutdown result = %q, want clean", got)
	}
	if got := counterOrGaugeValue(t, reg, "aegis_shutdowns_total", map[string]string{"result": "clean"}); got != 1 {
		t.Fatalf("shutdown counter = %v, want 1", got)
	}
}

func TestDrainTrackerShutdownForceClosesActiveTunnels(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	tracker := NewDrainTracker(slog.New(slog.NewTextHandler(io.Discard, nil)), m)

	closer := &spyCloser{}
	release := tracker.Track("passthrough", closer)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() {
		tracker.Shutdown(ctx)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Shutdown() did not return")
	}

	if !closer.closed {
		t.Fatal("expected active tunnel closer to be closed")
	}
	release()

	if got := counterOrGaugeValue(t, reg, "aegis_shutdowns_total", map[string]string{"result": "forced"}); got != 1 {
		t.Fatalf("shutdown counter = %v, want 1", got)
	}
	if got := counterOrGaugeValue(t, reg, "aegis_shutdown_forced_tunnel_closes_total", map[string]string{"mode": "passthrough"}); got != 1 {
		t.Fatalf("forced close counter = %v, want 1", got)
	}
}

type spyCloser struct {
	mu     sync.Mutex
	closed bool
}

func (c *spyCloser) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}

func counterOrGaugeValue(t *testing.T, reg *prometheus.Registry, name string, labels map[string]string) float64 {
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
			if !matchMetricLabels(metric.GetLabel(), labels) {
				continue
			}
			if metric.GetCounter() != nil {
				return metric.GetCounter().GetValue()
			}
			if metric.GetGauge() != nil {
				return metric.GetGauge().GetValue()
			}
			t.Fatalf("metric %q is neither counter nor gauge", name)
		}
	}

	t.Fatalf("metric %q with labels %#v not found", name, labels)
	return 0
}

func matchMetricLabels(pairs []*dto.LabelPair, labels map[string]string) bool {
	if len(pairs) != len(labels) {
		return false
	}
	for _, pair := range pairs {
		if labels[pair.GetName()] != pair.GetValue() {
			return false
		}
	}
	return true
}
