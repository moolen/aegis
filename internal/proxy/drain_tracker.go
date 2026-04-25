package proxy

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/moolen/aegis/internal/metrics"
)

type DrainTracker struct {
	logger  *slog.Logger
	metrics *metrics.Metrics

	mu     sync.Mutex
	active map[*trackedTunnel]struct{}
	wg     sync.WaitGroup
}

type trackedTunnel struct {
	mode    string
	closers []io.Closer
}

func NewDrainTracker(logger *slog.Logger, m *metrics.Metrics) *DrainTracker {
	if logger == nil {
		logger = slog.Default()
	}
	return &DrainTracker{
		logger:  logger,
		metrics: m,
		active:  make(map[*trackedTunnel]struct{}),
	}
}

func (t *DrainTracker) Track(mode string, closers ...io.Closer) func() {
	if t == nil {
		return func() {}
	}

	entry := &trackedTunnel{
		mode:    mode,
		closers: compactClosers(closers),
	}

	t.mu.Lock()
	t.active[entry] = struct{}{}
	t.wg.Add(1)
	t.mu.Unlock()
	t.recordActive(mode, 1)

	var once sync.Once
	return func() {
		once.Do(func() {
			t.mu.Lock()
			if _, ok := t.active[entry]; ok {
				delete(t.active, entry)
			}
			t.mu.Unlock()
			t.recordActive(mode, -1)
			t.wg.Done()
		})
	}
}

func (t *DrainTracker) ActiveCount() int {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.active)
}

func (t *DrainTracker) Shutdown(ctx context.Context) string {
	if t == nil {
		return "clean"
	}

	start := time.Now()
	done := make(chan struct{})
	go func() {
		t.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		t.recordShutdown("clean", time.Since(start), nil)
		return "clean"
	case <-ctx.Done():
		forced := t.forceCloseActive()
		t.recordShutdown("forced", time.Since(start), forced)
		return "forced"
	}
}

func (t *DrainTracker) forceCloseActive() map[string]int {
	t.mu.Lock()
	entries := make([]*trackedTunnel, 0, len(t.active))
	for entry := range t.active {
		entries = append(entries, entry)
	}
	t.mu.Unlock()

	forced := make(map[string]int)
	for _, entry := range entries {
		forced[entry.mode]++
		for _, closer := range entry.closers {
			_ = closer.Close()
		}
	}
	return forced
}

func (t *DrainTracker) recordActive(mode string, delta float64) {
	if t.metrics == nil {
		return
	}
	t.metrics.ConnectTunnelsActive.WithLabelValues(mode).Add(delta)
}

func (t *DrainTracker) recordShutdown(result string, duration time.Duration, forced map[string]int) {
	if t.metrics != nil {
		t.metrics.ShutdownsTotal.WithLabelValues(result).Inc()
		t.metrics.ShutdownDuration.Observe(duration.Seconds())
		for mode, count := range forced {
			t.metrics.ShutdownForcedTunnelCloses.WithLabelValues(mode).Add(float64(count))
		}
	}

	if result == "forced" {
		t.logger.Warn("shutdown forced active connect tunnels closed", "duration", duration, "forced", forced)
		return
	}
	t.logger.Info("shutdown drained cleanly", "duration", duration)
}

func compactClosers(in []io.Closer) []io.Closer {
	out := make([]io.Closer, 0, len(in))
	for _, closer := range in {
		if closer != nil {
			out = append(out, closer)
		}
	}
	return out
}
