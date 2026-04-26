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

func TestAdminServerRejectsUnauthorizedAdminRequest(t *testing.T) {
	srv := NewAdminServer("127.0.0.1:0", &enforcementAdminStub{token: "secret"})
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

func TestAdminServerReturnsAdminEnforcementStatus(t *testing.T) {
	admin := enforcementAdminStub{
		token: "secret",
		status: EnforcementStatus{
			Configured: "enforce",
			Override:   "audit",
			Effective:  "audit",
		},
	}
	srv := NewAdminServer("127.0.0.1:0", &admin)
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

func TestAdminServerReturnsAdminRuntimeStatus(t *testing.T) {
	admin := &enforcementAdminStub{
		token: "secret",
		runtime: RuntimeStatus{
			MITM: &MITMStatus{
				Enabled:               true,
				IssuerFingerprint:     "issuer-fp",
				CompanionFingerprints: []string{"old-fp"},
				AllFingerprints:       []string{"issuer-fp", "old-fp"},
			},
		},
	}

	srv := NewAdminServer("127.0.0.1:0", admin)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/admin/runtime", nil)
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

	var body RuntimeStatus
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if body.MITM == nil || body.MITM.IssuerFingerprint != "issuer-fp" {
		t.Fatalf("runtime MITM status = %#v, want issuer fingerprint", body.MITM)
	}
}

func TestAdminServerUpdatesAdminEnforcementMode(t *testing.T) {
	admin := &enforcementAdminStub{
		token: "secret",
		status: EnforcementStatus{
			Configured: "enforce",
			Effective:  "enforce",
		},
	}
	srv := NewAdminServer("127.0.0.1:0", admin)
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

func TestAdminServerReturnsIdentityDump(t *testing.T) {
	admin := &enforcementAdminStub{
		token: "secret",
		identities: []IdentityDumpRecord{{
			IP: "10.0.0.10",
			Effective: &IdentityRecord{
				Source:   "kubernetes",
				Provider: "cluster-a",
				Kind:     "kubernetes",
				Name:     "default/api",
			},
		}},
	}
	srv := NewAdminServer("127.0.0.1:0", admin)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/admin/identities", nil)
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

	var records []IdentityDumpRecord
	if err := json.NewDecoder(resp.Body).Decode(&records); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if len(records) != 1 || records[0].IP != "10.0.0.10" {
		t.Fatalf("records = %#v, want one identity dump record", records)
	}
}

func TestRuntimeSimulationReturnsProviderScopedDecision(t *testing.T) {
	admin := &enforcementAdminStub{
		token: "secret",
		simulation: SimulationResponse{
			Identity: &IdentityRecord{
				Source:   "kubernetes",
				Provider: "cluster-b",
				Kind:     "kubernetes",
				Name:     "default/web",
			},
			Action:        "deny",
			Reason:        "policy_denied",
			EffectiveMode: "enforce",
			Decision: &SimulationDecision{
				Allowed:           false,
				Policy:            "deny-cluster-a",
				PolicyEnforcement: "enforce",
			},
		},
	}
	srv := NewAdminServer("127.0.0.1:0", admin)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/admin/simulate?sourceIP=10.0.0.10&fqdn=example.com&port=443&protocol=connect", nil)
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
	if admin.lastSimulation.SourceIP != "10.0.0.10" || admin.lastSimulation.Protocol != "connect" {
		t.Fatalf("simulation request = %#v, want source IP and connect protocol", admin.lastSimulation)
	}

	var body SimulationResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if body.Identity == nil || body.Identity.Provider != "cluster-b" {
		t.Fatalf("identity = %#v, want provider cluster-b", body.Identity)
	}
	if body.Decision == nil || body.Decision.Policy != "deny-cluster-a" {
		t.Fatalf("decision = %#v, want deny-cluster-a", body.Decision)
	}
}

type readyCheckerFunc func() error

func (f readyCheckerFunc) CheckReadiness() error {
	return f()
}

type enforcementAdminStub struct {
	token          string
	status         EnforcementStatus
	runtime        RuntimeStatus
	lastMode       string
	identities     []IdentityDumpRecord
	simulation     SimulationResponse
	lastSimulation SimulationRequest
}

func (s *enforcementAdminStub) AdminToken() string {
	return s.token
}

func (s *enforcementAdminStub) EnforcementStatus() EnforcementStatus {
	return s.status
}

func (s *enforcementAdminStub) RuntimeStatus() RuntimeStatus {
	return s.runtime
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

func (s *enforcementAdminStub) DumpIdentities() []IdentityDumpRecord {
	return s.identities
}

func (s *enforcementAdminStub) Simulate(req SimulationRequest) (SimulationResponse, error) {
	s.lastSimulation = req
	return s.simulation, nil
}
