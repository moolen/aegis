package metrics

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func TestServerExposesHealthz(t *testing.T) {
	reg := prometheus.NewRegistry()
	srv := NewServer(":0", reg, nil, nil)
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
	srv := NewServer(":0", reg, nil, nil)
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
	srv := NewServer(":0", reg, readyCheckerFunc(func() error { return nil }), nil)
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
	srv := NewServer(":0", reg, readyCheckerFunc(func() error { return io.EOF }), nil)
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

func TestServerHidesAdminEndpointWithoutToken(t *testing.T) {
	reg := prometheus.NewRegistry()
	srv := NewServer(":0", reg, nil, &enforcementAdminStub{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/admin/enforcement")
	if err != nil {
		t.Fatalf("GET /admin/enforcement error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
}

func TestServerRejectsUnauthorizedAdminRequest(t *testing.T) {
	reg := prometheus.NewRegistry()
	srv := NewServer(":0", reg, nil, &enforcementAdminStub{token: "secret"})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/admin/enforcement?mode=audit", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do() error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
}

func TestServerReturnsAdminEnforcementStatus(t *testing.T) {
	reg := prometheus.NewRegistry()
	admin := enforcementAdminStub{
		token: "secret",
		status: EnforcementStatus{
			Configured: "enforce",
			Override:   "audit",
			Effective:  "audit",
		},
	}
	srv := NewServer(":0", reg, nil, &admin)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/admin/enforcement", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	req.Header.Set("Authorization", "Bearer secret")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do() error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var status EnforcementStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if status.Override != "audit" || status.Effective != "audit" {
		t.Fatalf("status = %#v, want override and effective audit", status)
	}
}

func TestServerUpdatesAdminEnforcementMode(t *testing.T) {
	reg := prometheus.NewRegistry()
	admin := &enforcementAdminStub{
		token: "secret",
		status: EnforcementStatus{
			Configured: "enforce",
			Effective:  "enforce",
		},
	}
	srv := NewServer(":0", reg, nil, admin)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/admin/enforcement?mode=audit", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	req.Header.Set("Authorization", "Bearer secret")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do() error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if admin.lastMode != "audit" {
		t.Fatalf("last mode = %q, want %q", admin.lastMode, "audit")
	}
	var status EnforcementStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if status.Override != "audit" || status.Effective != "audit" {
		t.Fatalf("status = %#v, want override and effective audit", status)
	}
}

type readyCheckerFunc func() error

func (f readyCheckerFunc) CheckReadiness() error {
	return f()
}

type enforcementAdminStub struct {
	token    string
	status   EnforcementStatus
	lastMode string
}

func (s *enforcementAdminStub) AdminToken() string {
	return s.token
}

func (s *enforcementAdminStub) EnforcementStatus() EnforcementStatus {
	return s.status
}

func (s *enforcementAdminStub) SetEnforcementMode(mode string) (EnforcementStatus, error) {
	s.lastMode = mode
	s.status.Override = mode
	if mode == "config" {
		s.status.Override = ""
		s.status.Effective = s.status.Configured
	} else {
		s.status.Effective = mode
	}
	return s.status, nil
}
