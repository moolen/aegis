package dns

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/moolen/aegis/internal/metrics"
)

func TestResolverCachesResults(t *testing.T) {
	calls := 0
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	r := NewResolver(Config{CacheTTL: time.Minute}, func(_ context.Context, host string) ([]net.IP, error) {
		calls++
		return []net.IP{net.ParseIP("127.0.0.1")}, nil
	}, slog.New(slog.NewTextHandler(io.Discard, nil)), m)

	_, _ = r.LookupNetIP(context.Background(), "example.com")
	_, _ = r.LookupNetIP(context.Background(), "example.com")

	if calls != 1 {
		t.Fatalf("resolver calls = %d, want 1", calls)
	}
}

func TestResolverReturnsLookupErrors(t *testing.T) {
	wantErr := errors.New("boom")
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	r := NewResolver(Config{CacheTTL: time.Minute}, func(_ context.Context, host string) ([]net.IP, error) {
		return nil, wantErr
	}, slog.New(slog.NewTextHandler(io.Discard, nil)), m)

	_, err := r.LookupNetIP(context.Background(), "example.com")
	if !errors.Is(err, wantErr) {
		t.Fatalf("LookupNetIP() error = %v, want %v", err, wantErr)
	}
}
