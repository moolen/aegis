package metrics

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func TestServerExposesHealthz(t *testing.T) {
	reg := prometheus.NewRegistry()
	srv := NewServer(":0", reg, nil)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

func TestServerExposesMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	New(reg)
	srv := NewServer(":0", reg, nil)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics error = %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if !strings.Contains(string(body), "go_gc_duration_seconds") {
		t.Fatalf("metrics output did not include Go collector")
	}
}

func TestServerExposesReadyzWhenCheckerIsHealthy(t *testing.T) {
	reg := prometheus.NewRegistry()
	srv := NewServer(":0", reg, readyCheckerFunc(func() error { return nil }))
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/readyz")
	if err != nil {
		t.Fatalf("GET /readyz error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

func TestServerExposesReadyzFailureWhenCheckerIsUnhealthy(t *testing.T) {
	reg := prometheus.NewRegistry()
	srv := NewServer(":0", reg, readyCheckerFunc(func() error { return io.EOF }))
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/readyz")
	if err != nil {
		t.Fatalf("GET /readyz error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusServiceUnavailable)
	}
}

type readyCheckerFunc func() error

func (f readyCheckerFunc) CheckReadiness() error {
	return f()
}
