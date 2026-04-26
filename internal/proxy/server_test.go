package proxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/moolen/aegis/internal/config"
	"github.com/moolen/aegis/internal/identity"
	"github.com/moolen/aegis/internal/metrics"
	"github.com/moolen/aegis/internal/policy"
)

const (
	testPolicyDiscoveryName = "proxy-test"
	testPolicyNamespace     = "default"
)

func TestProxyForwardsHTTPRequests(t *testing.T) {
	var receivedHost string

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHost = r.Host
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	proxyServer := httptest.NewServer(NewServer(Dependencies{
		Resolver: staticResolver{
			lookup: map[string][]net.IP{
				"service.internal": {net.ParseIP("127.0.0.1")},
			},
		},
		Metrics: m,
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
	}).Handler())
	defer proxyServer.Close()

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: func(*http.Request) (*url.URL, error) {
				return url.Parse(proxyServer.URL)
			},
		},
	}

	target := fmt.Sprintf("http://service.internal%s/healthz", upstreamURL.Host[strings.LastIndex(upstreamURL.Host, ":"):])
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do() error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}
	if receivedHost == "" || !strings.HasPrefix(receivedHost, "service.internal:") {
		t.Fatalf("received host = %q, want service.internal:<port>", receivedHost)
	}
}

func TestProxyDeniesHTTPRequestsBeforeDNSLookup(t *testing.T) {
	dnsCalls := 0
	proxyServer := httptest.NewServer(NewServer(Dependencies{
		Resolver: countingResolver{
			lookup: map[string][]net.IP{"example.com": {net.ParseIP("127.0.0.1")}},
			calls:  &dnsCalls,
		},
		IdentityResolver: staticIdentityResolver{
			identity: &identity.Identity{Labels: map[string]string{"app": "jobs"}},
		},
		PolicyEngine: mustPolicyEngine(t, []config.PolicyConfig{{
			Name: "allow-web",
			IdentitySelector: config.IdentitySelectorConfig{
				MatchLabels: map[string]string{"app": "web"},
			},
			Egress: []config.EgressRuleConfig{{
				FQDN:  "example.com",
				Ports: []int{80},
				TLS:   config.TLSRuleConfig{Mode: "mitm"},
				HTTP: &config.HTTPRuleConfig{
					AllowedMethods: []string{"GET"},
					AllowedPaths:   []string{"/*"},
				},
			}},
		}}),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}).Handler())
	defer proxyServer.Close()

	resp, err := proxiedRequest(proxyServer.URL, http.MethodGet, "http://example.com/", nil)
	if err != nil {
		t.Fatalf("proxiedRequest() error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
	if dnsCalls != 0 {
		t.Fatalf("dnsCalls = %d, want 0", dnsCalls)
	}
}

func TestProxyAllowsHTTPRequestsWhenPolicyMatches(t *testing.T) {
	var upstreamHits atomic.Int32

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		if r.Method != http.MethodGet {
			t.Fatalf("method = %q, want %q", r.Method, http.MethodGet)
		}
		if r.URL.Path != "/allowed" {
			t.Fatalf("path = %q, want %q", r.URL.Path, "/allowed")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	proxyServer := httptest.NewServer(NewServer(Dependencies{
		Resolver: staticResolver{
			lookup: map[string][]net.IP{"example.com": {net.ParseIP("127.0.0.1")}},
		},
		IdentityResolver: staticIdentityResolver{
			identity: &identity.Identity{Labels: map[string]string{"app": "web"}},
		},
		PolicyEngine: mustPolicyEngine(t, []config.PolicyConfig{{
			Name: "allow-web",
			IdentitySelector: config.IdentitySelectorConfig{
				MatchLabels: map[string]string{"app": "web"},
			},
			Egress: []config.EgressRuleConfig{{
				FQDN:  "example.com",
				Ports: []int{mustPort(t, upstreamURL.Host)},
				TLS:   config.TLSRuleConfig{Mode: "mitm"},
				HTTP: &config.HTTPRuleConfig{
					AllowedMethods: []string{"GET"},
					AllowedPaths:   []string{"/allowed"},
				},
			}},
		}}),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}).Handler())
	defer proxyServer.Close()

	resp, err := proxiedRequest(proxyServer.URL, http.MethodGet, fmt.Sprintf("http://example.com%s/allowed", hostPortSuffix(upstreamURL.Host)), nil)
	if err != nil {
		t.Fatalf("proxiedRequest() error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}
	if upstreamHits.Load() != 1 {
		t.Fatalf("upstreamHits = %d, want 1", upstreamHits.Load())
	}
}

func TestProxyReusesUpstreamHTTPConnectionAcrossRequests(t *testing.T) {
	var upstreamConnections atomic.Int32

	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	upstream.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			upstreamConnections.Add(1)
		}
	}
	upstream.Start()
	defer upstream.Close()

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	proxyServer := httptest.NewServer(NewServer(Dependencies{
		Resolver: staticResolver{
			lookup: map[string][]net.IP{"example.com": {net.ParseIP("127.0.0.1")}},
		},
		IdentityResolver: staticIdentityResolver{
			identity: &identity.Identity{Labels: map[string]string{"app": "web"}},
		},
		PolicyEngine: mustPolicyEngine(t, []config.PolicyConfig{{
			Name:             "allow-web",
			IdentitySelector: config.IdentitySelectorConfig{MatchLabels: map[string]string{"app": "web"}},
			Egress: []config.EgressRuleConfig{{
				FQDN:  "example.com",
				Ports: []int{mustPort(t, upstreamURL.Host)},
				TLS:   config.TLSRuleConfig{Mode: "mitm"},
				HTTP: &config.HTTPRuleConfig{
					AllowedMethods: []string{"GET"},
					AllowedPaths:   []string{"/allowed"},
				},
			}},
		}}),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}).Handler())
	defer proxyServer.Close()

	targetURL := fmt.Sprintf("http://example.com%s/allowed", hostPortSuffix(upstreamURL.Host))
	for i := 0; i < 3; i++ {
		resp, err := proxiedRequest(proxyServer.URL, http.MethodGet, targetURL, nil)
		if err != nil {
			t.Fatalf("proxiedRequest() error = %v", err)
		}
		if resp.StatusCode != http.StatusNoContent {
			resp.Body.Close()
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
		}
		resp.Body.Close()
	}

	if got := upstreamConnections.Load(); got != 1 {
		t.Fatalf("upstreamConnections = %d, want 1", got)
	}
}

func TestRemoveHopByHopHeadersRemovesConnectionTokens(t *testing.T) {
	header := http.Header{
		"Connection":        []string{"Keep-Alive, Foo, Bar"},
		"Proxy-Connection":  []string{"close"},
		"Keep-Alive":        []string{"timeout=5"},
		"Foo":               []string{"remove-me"},
		"Bar":               []string{"remove-me-too"},
		"X-End-To-End":      []string{"keep-me"},
		"Transfer-Encoding": []string{"chunked"},
	}

	removeHopByHopHeaders(header)

	if got := header.Values("Foo"); len(got) != 0 {
		t.Fatalf("Foo header still present: %#v", got)
	}
	if got := header.Values("Bar"); len(got) != 0 {
		t.Fatalf("Bar header still present: %#v", got)
	}
	if got := header.Values("Connection"); len(got) != 0 {
		t.Fatalf("Connection header still present: %#v", got)
	}
	if got := header.Values("Proxy-Connection"); len(got) != 0 {
		t.Fatalf("Proxy-Connection header still present: %#v", got)
	}
	if got := header.Values("Keep-Alive"); len(got) != 0 {
		t.Fatalf("Keep-Alive header still present: %#v", got)
	}
	if got := header.Values("Transfer-Encoding"); len(got) != 0 {
		t.Fatalf("Transfer-Encoding header still present: %#v", got)
	}
	if got := header.Values("X-End-To-End"); len(got) != 1 || got[0] != "keep-me" {
		t.Fatalf("X-End-To-End header = %#v, want [keep-me]", got)
	}
}

func TestProxyConnectionLimiterRejectsSecondConcurrentHTTPRequest(t *testing.T) {
	upstreamStarted := make(chan struct{}, 1)
	releaseUpstream := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamStarted <- struct{}{}
		<-releaseUpstream
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	connectionLimiter := NewConnectionLimiter(slog.New(slog.NewTextHandler(io.Discard, nil)), m)
	connectionLimiter.UpdateLimit(1)

	proxyServer := httptest.NewServer(NewServer(Dependencies{
		Resolver: staticResolver{
			lookup: map[string][]net.IP{"example.com": {net.ParseIP("127.0.0.1")}},
		},
		ConnectionLimiter: connectionLimiter,
		IdentityResolver: staticIdentityResolver{
			identity: &identity.Identity{Name: "default/web", Labels: map[string]string{"app": "web"}},
		},
		PolicyEngine: mustPolicyEngine(t, []config.PolicyConfig{{
			Name: "allow-web",
			IdentitySelector: config.IdentitySelectorConfig{
				MatchLabels: map[string]string{"app": "web"},
			},
			Egress: []config.EgressRuleConfig{{
				FQDN:  "example.com",
				Ports: []int{mustPort(t, upstreamURL.Host)},
				TLS:   config.TLSRuleConfig{Mode: "mitm"},
				HTTP: &config.HTTPRuleConfig{
					AllowedMethods: []string{"GET"},
					AllowedPaths:   []string{"/allowed"},
				},
			}},
		}}),
		Metrics: m,
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
	}).Handler())
	defer proxyServer.Close()

	firstDone := make(chan *http.Response, 1)
	firstErr := make(chan error, 1)
	go func() {
		resp, reqErr := proxiedRequest(proxyServer.URL, http.MethodGet, fmt.Sprintf("http://example.com%s/allowed", hostPortSuffix(upstreamURL.Host)), nil)
		if reqErr != nil {
			firstErr <- reqErr
			return
		}
		firstDone <- resp
	}()

	select {
	case <-upstreamStarted:
	case err := <-firstErr:
		t.Fatalf("first proxiedRequest() error = %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for first request to reach upstream")
	}

	resp, err := proxiedRequest(proxyServer.URL, http.MethodGet, fmt.Sprintf("http://example.com%s/allowed", hostPortSuffix(upstreamURL.Host)), nil)
	if err != nil {
		t.Fatalf("second proxiedRequest() error = %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second status = %d, want %d", resp.StatusCode, http.StatusTooManyRequests)
	}

	close(releaseUpstream)

	select {
	case resp := <-firstDone:
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("first status = %d, want %d", resp.StatusCode, http.StatusNoContent)
		}
	case err := <-firstErr:
		t.Fatalf("first proxiedRequest() error = %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for first response")
	}

	if got := counterValue(t, reg, "aegis_identity_connection_limit_rejections_total", map[string]string{"protocol": "http"}); got != 1 {
		t.Fatalf("http limit rejection metric = %v, want 1", got)
	}
	if got := counterValue(t, reg, "aegis_request_decisions_total", map[string]string{
		"protocol": "http",
		"action":   "deny",
		"policy":   "allow-web",
		"reason":   "connection_limit_exceeded",
	}); got != 1 {
		t.Fatalf("deny decision metric = %v, want 1", got)
	}
	if got := gaugeValue(t, reg, "aegis_identity_connections_active", map[string]string{"protocol": "http"}); got != 0 {
		t.Fatalf("http active gauge = %v, want 0", got)
	}
}

func TestProxyRecordsHTTPDecisionAndPolicyDurationMetrics(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	proxyServer := httptest.NewServer(NewServer(Dependencies{
		Resolver: staticResolver{
			lookup: map[string][]net.IP{"example.com": {net.ParseIP("127.0.0.1")}},
		},
		DestinationGuard: mustDestinationGuard(t, nil, []string{"127.0.0.0/8"}),
		IdentityResolver: staticIdentityResolver{
			identity: &identity.Identity{Labels: map[string]string{"app": "web"}},
		},
		PolicyEngine: mustPolicyEngine(t, []config.PolicyConfig{{
			Name:             "allow-web",
			IdentitySelector: config.IdentitySelectorConfig{MatchLabels: map[string]string{"app": "web"}},
			Egress: []config.EgressRuleConfig{{
				FQDN:  "example.com",
				Ports: []int{mustPort(t, upstreamURL.Host)},
				TLS:   config.TLSRuleConfig{Mode: "mitm"},
				HTTP: &config.HTTPRuleConfig{
					AllowedMethods: []string{"GET"},
					AllowedPaths:   []string{"/*"},
				},
			}},
		}}),
		Metrics: m,
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
	}).Handler())
	defer proxyServer.Close()

	resp, err := proxiedRequest(proxyServer.URL, http.MethodGet, fmt.Sprintf("http://example.com%s/", hostPortSuffix(upstreamURL.Host)), nil)
	if err != nil {
		t.Fatalf("proxiedRequest() error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}
	if got := counterValue(t, reg, "aegis_request_decisions_total", map[string]string{
		"protocol": "http",
		"action":   "allow",
		"policy":   "allow-web",
		"reason":   "policy_allowed",
	}); got != 1 {
		t.Fatalf("decision metric = %v, want 1", got)
	}
	if got := histogramSampleCount(t, reg, "aegis_policy_evaluation_duration_seconds", map[string]string{"protocol": "http"}); got != 1 {
		t.Fatalf("policy evaluation count = %d, want 1", got)
	}
}

func TestProxyRecordsDeniedHTTPDecisionMetric(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	proxyServer := httptest.NewServer(NewServer(Dependencies{
		Resolver: staticResolver{
			lookup: map[string][]net.IP{"example.com": {net.ParseIP("127.0.0.1")}},
		},
		IdentityResolver: staticIdentityResolver{
			identity: &identity.Identity{Labels: map[string]string{"app": "jobs"}},
		},
		PolicyEngine: mustPolicyEngine(t, []config.PolicyConfig{{
			Name: "allow-web",
			IdentitySelector: config.IdentitySelectorConfig{
				MatchLabels: map[string]string{"app": "web"},
			},
			Egress: []config.EgressRuleConfig{{
				FQDN:  "example.com",
				Ports: []int{80},
				TLS:   config.TLSRuleConfig{Mode: "mitm"},
				HTTP: &config.HTTPRuleConfig{
					AllowedMethods: []string{"GET"},
					AllowedPaths:   []string{"/*"},
				},
			}},
		}}),
		Metrics: m,
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
	}).Handler())
	defer proxyServer.Close()

	resp, err := proxiedRequest(proxyServer.URL, http.MethodGet, "http://example.com/", nil)
	if err != nil {
		t.Fatalf("proxiedRequest() error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
	if got := counterValue(t, reg, "aegis_request_decisions_total", map[string]string{
		"protocol": "http",
		"action":   "deny",
		"policy":   "none",
		"reason":   "policy_denied",
	}); got != 1 {
		t.Fatalf("decision metric = %v, want 1", got)
	}
}

func TestProxyAuditModeAllowsDeniedHTTPRequestsAndRecordsWouldDeny(t *testing.T) {
	var upstreamHits atomic.Int32

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	proxyServer := httptest.NewServer(NewServer(Dependencies{
		Resolver: staticResolver{
			lookup: map[string][]net.IP{"example.com": {net.ParseIP("127.0.0.1")}},
		},
		EnforcementMode: "audit",
		IdentityResolver: staticIdentityResolver{
			identity: &identity.Identity{Name: "default/web", Labels: map[string]string{"app": "web"}},
		},
		PolicyEngine: mustPolicyEngine(t, []config.PolicyConfig{{
			Name:             "allow-post-only",
			IdentitySelector: config.IdentitySelectorConfig{MatchLabels: map[string]string{"app": "web"}},
			Egress: []config.EgressRuleConfig{{
				FQDN:  "example.com",
				Ports: []int{mustPort(t, upstreamURL.Host)},
				TLS:   config.TLSRuleConfig{Mode: "mitm"},
				HTTP: &config.HTTPRuleConfig{
					AllowedMethods: []string{"POST"},
					AllowedPaths:   []string{"/*"},
				},
			}},
		}}),
		Metrics: m,
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
	}).Handler())
	defer proxyServer.Close()

	resp, err := proxiedRequest(proxyServer.URL, http.MethodGet, fmt.Sprintf("http://example.com%s/blocked", hostPortSuffix(upstreamURL.Host)), nil)
	if err != nil {
		t.Fatalf("proxiedRequest() error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}
	if upstreamHits.Load() != 1 {
		t.Fatalf("upstreamHits = %d, want 1", upstreamHits.Load())
	}
	if got := counterValue(t, reg, "aegis_request_decisions_total", map[string]string{
		"protocol": "http",
		"action":   "allow",
		"policy":   "allow-post-only",
		"reason":   "audit_policy_denied",
	}); got != 1 {
		t.Fatalf("actual decision metric = %v, want 1", got)
	}
	if got := counterValue(t, reg, "aegis_audit_decisions_total", map[string]string{
		"protocol": "http",
		"action":   "would_deny",
		"identity": "default/web",
		"fqdn":     "example.com",
		"policy":   "allow-post-only",
		"reason":   "policy_denied",
	}); got != 1 {
		t.Fatalf("audit decision metric = %v, want 1", got)
	}
}

func TestProxyPolicyLevelAuditAllowsDeniedHTTPRequests(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	proxyServer := httptest.NewServer(NewServer(Dependencies{
		Resolver: staticResolver{
			lookup: map[string][]net.IP{"example.com": {net.ParseIP("127.0.0.1")}},
		},
		IdentityResolver: staticIdentityResolver{
			identity: &identity.Identity{Name: "default/web", Labels: map[string]string{"app": "web"}},
		},
		PolicyEngine: mustPolicyEngine(t, []config.PolicyConfig{{
			Name:        "legacy-web",
			Enforcement: "audit",
			IdentitySelector: config.IdentitySelectorConfig{
				MatchLabels: map[string]string{"app": "web"},
			},
			Egress: []config.EgressRuleConfig{{
				FQDN:  "example.com",
				Ports: []int{mustPort(t, upstreamURL.Host)},
				TLS:   config.TLSRuleConfig{Mode: "mitm"},
				HTTP: &config.HTTPRuleConfig{
					AllowedMethods: []string{"POST"},
					AllowedPaths:   []string{"/*"},
				},
			}},
		}}),
		Metrics: m,
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
	}).Handler())
	defer proxyServer.Close()

	resp, err := proxiedRequest(proxyServer.URL, http.MethodGet, fmt.Sprintf("http://example.com%s/blocked", hostPortSuffix(upstreamURL.Host)), nil)
	if err != nil {
		t.Fatalf("proxiedRequest() error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}
	if got := counterValue(t, reg, "aegis_request_decisions_total", map[string]string{
		"protocol": "http",
		"action":   "allow",
		"policy":   "legacy-web",
		"reason":   "audit_policy_denied",
	}); got != 1 {
		t.Fatalf("actual decision metric = %v, want 1", got)
	}
}

func TestProxyUnknownIdentityDenyBlocksHTTPRequests(t *testing.T) {
	var upstreamHits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	proxyServer := httptest.NewServer(NewServer(Dependencies{
		Resolver: staticResolver{
			lookup: map[string][]net.IP{"example.com": {net.ParseIP("127.0.0.1")}},
		},
		UnknownIdentityPolicy: "deny",
		Metrics:               m,
		Logger:                slog.New(slog.NewTextHandler(io.Discard, nil)),
	}).Handler())
	defer proxyServer.Close()

	resp, err := proxiedRequest(proxyServer.URL, http.MethodGet, fmt.Sprintf("http://example.com%s/allowed", hostPortSuffix(upstreamURL.Host)), nil)
	if err != nil {
		t.Fatalf("proxiedRequest() error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
	if upstreamHits.Load() != 0 {
		t.Fatalf("upstreamHits = %d, want 0", upstreamHits.Load())
	}
	if got := counterValue(t, reg, "aegis_request_decisions_total", map[string]string{
		"protocol": "http",
		"action":   "deny",
		"policy":   "none",
		"reason":   "unknown_identity",
	}); got != 1 {
		t.Fatalf("decision metric = %v, want 1", got)
	}
}

func TestServerAllowsCIDRSubjectWithoutResolvedIdentity(t *testing.T) {
	var upstreamHits atomic.Int32

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	server := NewServer(Dependencies{
		Resolver: staticResolver{
			lookup: map[string][]net.IP{"example.com": {net.ParseIP("127.0.0.1")}},
		},
		IdentityResolver:      staticIdentityResolver{},
		UnknownIdentityPolicy: "deny",
		PolicyEngine: mustPolicyEngine(t, []config.PolicyConfig{{
			Name: "allow-loopback-cidr",
			Subjects: config.PolicySubjectsConfig{
				CIDRs: []string{"10.20.0.0/24"},
			},
			Egress: []config.EgressRuleConfig{{
				FQDN:  "example.com",
				Ports: []int{mustPort(t, upstreamURL.Host)},
				TLS:   config.TLSRuleConfig{Mode: "mitm"},
				HTTP: &config.HTTPRuleConfig{
					AllowedMethods: []string{"GET"},
					AllowedPaths:   []string{"/allowed"},
				},
			}},
		}}),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})

	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("http://example.com%s/allowed", hostPortSuffix(upstreamURL.Host)), nil)
	req.RemoteAddr = "10.20.0.10:1234"

	resp := httptest.NewRecorder()
	server.Handler().ServeHTTP(resp, req)

	if resp.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", resp.Code, http.StatusNoContent)
	}
	if upstreamHits.Load() != 1 {
		t.Fatalf("upstreamHits = %d, want 1", upstreamHits.Load())
	}
}

func TestProxyConnectAllowsCIDRSubjectWithoutResolvedIdentityWhenUnknownIdentityDenied(t *testing.T) {
	clientHello := mustClientHello(t, "tunnel.internal")

	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer upstream.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, acceptErr := upstream.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, len(clientHello)+4)
		_, _ = io.ReadFull(conn, buf)
		_, _ = conn.Write([]byte("pong"))
	}()

	proxyServer := httptest.NewServer(NewServer(Dependencies{
		Resolver: staticResolver{
			lookup: map[string][]net.IP{
				"tunnel.internal": {net.ParseIP("127.0.0.1")},
			},
		},
		IdentityResolver:      staticIdentityResolver{},
		UnknownIdentityPolicy: "deny",
		PolicyEngine: mustPolicyEngine(t, []config.PolicyConfig{{
			Name: "allow-source-cidr",
			Subjects: config.PolicySubjectsConfig{
				CIDRs: []string{"127.0.0.0/8"},
			},
			Egress: []config.EgressRuleConfig{{
				FQDN:  "tunnel.internal",
				Ports: []int{mustPort(t, upstream.Addr().String())},
				TLS:   config.TLSRuleConfig{Mode: "passthrough"},
			}},
		}}),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}).Handler())
	defer proxyServer.Close()

	conn, reader := mustConnectProxy(t, proxyServer.URL, fmt.Sprintf("tunnel.internal:%s", strings.TrimPrefix(upstream.Addr().String(), "127.0.0.1:")))
	defer conn.Close()
	readConnectEstablished(t, reader)

	if _, err := conn.Write(append(clientHello, []byte("ping")...)); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(reader, reply); err != nil {
		t.Fatalf("ReadFull() error = %v", err)
	}
	if string(reply) != "pong" {
		t.Fatalf("reply = %q, want %q", string(reply), "pong")
	}

	_ = conn.Close()
	<-done
}

func TestProxyBypassPolicyAllowsDeniedHTTPRequestsAndRecordsWouldDeny(t *testing.T) {
	var upstreamHits atomic.Int32

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	proxyServer := httptest.NewServer(NewServer(Dependencies{
		Resolver: staticResolver{
			lookup: map[string][]net.IP{"example.com": {net.ParseIP("127.0.0.1")}},
		},
		IdentityResolver: staticIdentityResolver{
			identity: &identity.Identity{Name: "default/web", Labels: map[string]string{"app": "web"}},
		},
		PolicyEngine: mustPolicyEngine(t, []config.PolicyConfig{{
			Name:   "break-glass",
			Bypass: true,
			IdentitySelector: config.IdentitySelectorConfig{
				MatchLabels: map[string]string{"app": "web"},
			},
			Egress: []config.EgressRuleConfig{{
				FQDN:  "example.com",
				Ports: []int{mustPort(t, upstreamURL.Host)},
				TLS:   config.TLSRuleConfig{Mode: "mitm"},
				HTTP: &config.HTTPRuleConfig{
					AllowedMethods: []string{"POST"},
					AllowedPaths:   []string{"/*"},
				},
			}},
		}}),
		Metrics: m,
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
	}).Handler())
	defer proxyServer.Close()

	resp, err := proxiedRequest(proxyServer.URL, http.MethodGet, fmt.Sprintf("http://example.com%s/blocked", hostPortSuffix(upstreamURL.Host)), nil)
	if err != nil {
		t.Fatalf("proxiedRequest() error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}
	if upstreamHits.Load() != 1 {
		t.Fatalf("upstreamHits = %d, want 1", upstreamHits.Load())
	}
	if got := counterValue(t, reg, "aegis_request_decisions_total", map[string]string{
		"protocol": "http",
		"action":   "allow",
		"policy":   "break-glass",
		"reason":   "audit_policy_denied",
	}); got != 1 {
		t.Fatalf("actual decision metric = %v, want 1", got)
	}
	if got := counterValue(t, reg, "aegis_audit_decisions_total", map[string]string{
		"protocol": "http",
		"action":   "would_deny",
		"identity": "default/web",
		"fqdn":     "example.com",
		"policy":   "break-glass",
		"reason":   "policy_denied",
	}); got != 1 {
		t.Fatalf("audit decision metric = %v, want 1", got)
	}
}

func TestProxyBlocksHTTPRequestsToDirectLoopbackIP(t *testing.T) {
	proxyServer := httptest.NewServer(NewServer(Dependencies{
		DestinationGuard: mustDestinationGuard(t, nil, nil),
		PolicyEngine: mustPolicyEngine(t, []config.PolicyConfig{{
			Name:             "allow-all",
			IdentitySelector: config.IdentitySelectorConfig{MatchLabels: map[string]string{}},
			Egress: []config.EgressRuleConfig{{
				FQDN:  "*",
				Ports: []int{8080},
				TLS:   config.TLSRuleConfig{Mode: "mitm"},
				HTTP: &config.HTTPRuleConfig{
					AllowedMethods: []string{"GET"},
					AllowedPaths:   []string{"/*"},
				},
			}},
		}}),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}).Handler())
	defer proxyServer.Close()

	resp, err := proxiedRequest(proxyServer.URL, http.MethodGet, "http://127.0.0.1:8080/", nil)
	if err != nil {
		t.Fatalf("proxiedRequest() error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
}

func TestProxyBlocksDNSRebindingToPrivateAddress(t *testing.T) {
	dnsCalls := 0
	proxyServer := httptest.NewServer(NewServer(Dependencies{
		Resolver: countingResolver{
			lookup: map[string][]net.IP{"example.com": {net.ParseIP("127.0.0.1")}},
			calls:  &dnsCalls,
		},
		DestinationGuard: mustDestinationGuard(t, nil, nil),
		IdentityResolver: staticIdentityResolver{
			identity: &identity.Identity{Labels: map[string]string{"app": "web"}},
		},
		PolicyEngine: mustPolicyEngine(t, []config.PolicyConfig{{
			Name:             "allow-web",
			IdentitySelector: config.IdentitySelectorConfig{MatchLabels: map[string]string{"app": "web"}},
			Egress: []config.EgressRuleConfig{{
				FQDN:  "example.com",
				Ports: []int{80},
				TLS:   config.TLSRuleConfig{Mode: "mitm"},
				HTTP: &config.HTTPRuleConfig{
					AllowedMethods: []string{"GET"},
					AllowedPaths:   []string{"/*"},
				},
			}},
		}}),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}).Handler())
	defer proxyServer.Close()

	resp, err := proxiedRequest(proxyServer.URL, http.MethodGet, "http://example.com/", nil)
	if err != nil {
		t.Fatalf("proxiedRequest() error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
	if dnsCalls != 1 {
		t.Fatalf("dnsCalls = %d, want 1", dnsCalls)
	}
}

func TestProxyAllowsExplicitlyAllowlistedInternalHostname(t *testing.T) {
	var upstreamHits atomic.Int32

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	proxyServer := httptest.NewServer(NewServer(Dependencies{
		Resolver: staticResolver{
			lookup: map[string][]net.IP{"service.internal": {net.ParseIP("127.0.0.1")}},
		},
		DestinationGuard: mustDestinationGuard(t, []string{"service.internal"}, nil),
		IdentityResolver: staticIdentityResolver{
			identity: &identity.Identity{Labels: map[string]string{"app": "web"}},
		},
		PolicyEngine: mustPolicyEngine(t, []config.PolicyConfig{{
			Name:             "allow-web",
			IdentitySelector: config.IdentitySelectorConfig{MatchLabels: map[string]string{"app": "web"}},
			Egress: []config.EgressRuleConfig{{
				FQDN:  "service.internal",
				Ports: []int{mustPort(t, upstreamURL.Host)},
				TLS:   config.TLSRuleConfig{Mode: "mitm"},
				HTTP: &config.HTTPRuleConfig{
					AllowedMethods: []string{"GET"},
					AllowedPaths:   []string{"/*"},
				},
			}},
		}}),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}).Handler())
	defer proxyServer.Close()

	resp, err := proxiedRequest(proxyServer.URL, http.MethodGet, fmt.Sprintf("http://service.internal%s/", hostPortSuffix(upstreamURL.Host)), nil)
	if err != nil {
		t.Fatalf("proxiedRequest() error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}
	if upstreamHits.Load() != 1 {
		t.Fatalf("upstreamHits = %d, want 1", upstreamHits.Load())
	}
}

func TestProxyDeniesHTTPRequestsWithoutHittingUpstream(t *testing.T) {
	var upstreamHits atomic.Int32
	dnsCalls := 0

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	proxyServer := httptest.NewServer(NewServer(Dependencies{
		Resolver: countingResolver{
			lookup: map[string][]net.IP{"example.com": {net.ParseIP("127.0.0.1")}},
			calls:  &dnsCalls,
		},
		IdentityResolver: staticIdentityResolver{
			identity: &identity.Identity{Labels: map[string]string{"app": "web"}},
		},
		PolicyEngine: mustPolicyEngine(t, []config.PolicyConfig{{
			Name: "allow-web",
			IdentitySelector: config.IdentitySelectorConfig{
				MatchLabels: map[string]string{"app": "web"},
			},
			Egress: []config.EgressRuleConfig{{
				FQDN:  "example.com",
				Ports: []int{mustPort(t, upstreamURL.Host)},
				TLS:   config.TLSRuleConfig{Mode: "mitm"},
				HTTP: &config.HTTPRuleConfig{
					AllowedMethods: []string{"POST"},
					AllowedPaths:   []string{"/*"},
				},
			}},
		}}),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}).Handler())
	defer proxyServer.Close()

	resp, err := proxiedRequest(proxyServer.URL, http.MethodGet, fmt.Sprintf("http://example.com%s/blocked", hostPortSuffix(upstreamURL.Host)), nil)
	if err != nil {
		t.Fatalf("proxiedRequest() error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
	if upstreamHits.Load() != 0 {
		t.Fatalf("upstreamHits = %d, want 0", upstreamHits.Load())
	}
	if dnsCalls != 0 {
		t.Fatalf("dnsCalls = %d, want 0", dnsCalls)
	}
}

func TestProxyEvaluatesPolicyAgainstEscapedPath(t *testing.T) {
	var seenPolicyPath string
	var upstreamRequestURI string

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamRequestURI = r.RequestURI
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	proxyServer := httptest.NewServer(NewServer(Dependencies{
		Resolver: staticResolver{
			lookup: map[string][]net.IP{"example.com": {net.ParseIP("127.0.0.1")}},
		},
		IdentityResolver: staticIdentityResolver{
			identity: &identity.Identity{Labels: map[string]string{"app": "web"}},
		},
		PolicyEngine: &policyEngineStub{
			evaluate: func(id *identity.Identity, sourceIP netip.Addr, fqdn string, port int, method string, reqPath string) *policy.Decision {
				seenPolicyPath = reqPath
				if reqPath == "/api%2Fsecret" {
					return &policy.Decision{Allowed: true}
				}
				return &policy.Decision{}
			},
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}).Handler())
	defer proxyServer.Close()

	resp, err := proxiedRequest(proxyServer.URL, http.MethodGet, fmt.Sprintf("http://example.com%s/api%%2Fsecret", hostPortSuffix(upstreamURL.Host)), nil)
	if err != nil {
		t.Fatalf("proxiedRequest() error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}
	if seenPolicyPath != "/api%2Fsecret" {
		t.Fatalf("policy path = %q, want %q", seenPolicyPath, "/api%2Fsecret")
	}
	if upstreamRequestURI != "/api%2Fsecret" {
		t.Fatalf("upstream request URI = %q, want %q", upstreamRequestURI, "/api%2Fsecret")
	}
}

func TestProxyRemoteAddrFeedsIdentityResolver(t *testing.T) {
	var resolvedIP net.IP
	var policyIdentity *identity.Identity

	server := NewServer(Dependencies{
		IdentityResolver: &spyIdentityResolver{
			resolve: func(ip net.IP) (*identity.Identity, error) {
				resolvedIP = append(net.IP(nil), ip...)
				return &identity.Identity{Labels: map[string]string{"app": "web"}}, nil
			},
		},
		PolicyEngine: &policyEngineStub{
			evaluate: func(id *identity.Identity, sourceIP netip.Addr, fqdn string, port int, method string, reqPath string) *policy.Decision {
				policyIdentity = id
				return &policy.Decision{}
			},
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.RemoteAddr = "203.0.113.9:4567"

	resp := httptest.NewRecorder()
	server.Handler().ServeHTTP(resp, req)

	if resp.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", resp.Code, http.StatusForbidden)
	}
	if resolvedIP == nil || !resolvedIP.Equal(net.ParseIP("203.0.113.9")) {
		t.Fatalf("resolved IP = %v, want %v", resolvedIP, net.ParseIP("203.0.113.9"))
	}
	if policyIdentity == nil || policyIdentity.Labels["app"] != "web" {
		t.Fatalf("policy identity = %#v, want app=web", policyIdentity)
	}
}

func TestProxyFallsBackToUnknownIdentity(t *testing.T) {
	tests := []struct {
		name           string
		remoteAddr     string
		resolver       *spyIdentityResolver
		wantCalls      int
		wantUnknownApp bool
	}{
		{
			name:           "malformed remote addr",
			remoteAddr:     "malformed",
			resolver:       &spyIdentityResolver{},
			wantCalls:      0,
			wantUnknownApp: true,
		},
		{
			name:       "resolver error",
			remoteAddr: "203.0.113.10:4567",
			resolver: &spyIdentityResolver{
				resolve: func(net.IP) (*identity.Identity, error) {
					return nil, errors.New("boom")
				},
			},
			wantCalls:      1,
			wantUnknownApp: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var policyIdentity *identity.Identity

			server := NewServer(Dependencies{
				IdentityResolver: tc.resolver,
				PolicyEngine: &policyEngineStub{
					evaluate: func(id *identity.Identity, sourceIP netip.Addr, fqdn string, port int, method string, reqPath string) *policy.Decision {
						policyIdentity = id
						return &policy.Decision{}
					},
				},
				Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
			})

			req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
			req.RemoteAddr = tc.remoteAddr

			resp := httptest.NewRecorder()
			server.Handler().ServeHTTP(resp, req)

			if resp.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want %d", resp.Code, http.StatusForbidden)
			}
			if tc.resolver.calls != tc.wantCalls {
				t.Fatalf("resolver calls = %d, want %d", tc.resolver.calls, tc.wantCalls)
			}
			if policyIdentity == nil {
				t.Fatal("policy identity = nil, want unknown identity")
			}
			if policyIdentity.Source != "unknown" || policyIdentity.Name != "unknown" {
				t.Fatalf("policy identity = %#v, want unknown identity", policyIdentity)
			}
			if tc.wantUnknownApp && policyIdentity.Labels["app"] != "" {
				t.Fatalf("policy identity labels = %#v, want missing app label", policyIdentity.Labels)
			}
		})
	}
}

func TestProxyEstablishesConnectTunnel(t *testing.T) {
	clientHello := mustClientHello(t, "tunnel.internal")

	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer upstream.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, acceptErr := upstream.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, len(clientHello)+4)
		_, _ = io.ReadFull(conn, buf)
		if !bytes.Equal(buf[:len(clientHello)], clientHello) {
			t.Fatal("upstream did not receive expected client hello")
		}
		_, _ = conn.Write([]byte("pong"))
	}()

	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	proxyServer := httptest.NewServer(NewServer(Dependencies{
		Resolver: staticResolver{
			lookup: map[string][]net.IP{
				"tunnel.internal": {net.ParseIP("127.0.0.1")},
			},
		},
		Metrics: m,
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
	}).Handler())
	defer proxyServer.Close()

	proxyURL, err := url.Parse(proxyServer.URL)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	conn, err := net.Dial("tcp", proxyURL.Host)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer conn.Close()

	target := fmt.Sprintf("tunnel.internal:%s", strings.TrimPrefix(upstream.Addr().String(), "127.0.0.1:"))
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		t.Fatalf("Fprintf() error = %v", err)
	}

	reader := bufio.NewReader(conn)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("ReadString() error = %v", err)
	}
	if !strings.Contains(statusLine, "200") {
		t.Fatalf("unexpected status line %q", statusLine)
	}

	for {
		line, readErr := reader.ReadString('\n')
		if readErr != nil {
			t.Fatalf("reading headers: %v", readErr)
		}
		if line == "\r\n" {
			break
		}
	}

	if _, err := conn.Write(append(clientHello, []byte("ping")...)); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	reply := make([]byte, 4)
	if _, err := io.ReadFull(reader, reply); err != nil {
		t.Fatalf("ReadFull() error = %v", err)
	}
	if string(reply) != "pong" {
		t.Fatalf("reply = %q, want %q", string(reply), "pong")
	}
	if got := counterValue(t, reg, "aegis_connect_tunnels_total", map[string]string{"mode": "passthrough", "result": "established"}); got != 1 {
		t.Fatalf("connect tunnel metric = %v, want 1", got)
	}

	<-done
}

func TestProxyConnectUsesIdentityResolverAndPolicyEngine(t *testing.T) {
	clientHello := mustClientHello(t, "tunnel.internal")

	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer upstream.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, acceptErr := upstream.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, len(clientHello)+4)
		_, _ = io.ReadFull(conn, buf)
		_, _ = conn.Write([]byte("pong"))
	}()

	identityResolver := &spyIdentityResolver{
		resolve: func(net.IP) (*identity.Identity, error) {
			return &identity.Identity{Labels: map[string]string{"app": "web"}}, nil
		},
	}
	policyEngine := &policyEngineStub{
		evaluate: func(id *identity.Identity, sourceIP netip.Addr, fqdn string, port int, method string, reqPath string) *policy.Decision {
			t.Fatal("http policy evaluation should not be called for CONNECT")
			return nil
		},
		evaluateConnect: func(id *identity.Identity, sourceIP netip.Addr, fqdn string, port int) *policy.Decision {
			if id == nil || id.Labels["app"] != "web" {
				t.Fatalf("connect policy identity = %#v, want app=web", id)
			}
			if fqdn != "tunnel.internal" {
				t.Fatalf("fqdn = %q, want %q", fqdn, "tunnel.internal")
			}
			return &policy.Decision{Allowed: true, TLSMode: "passthrough"}
		},
	}

	proxyServer := httptest.NewServer(NewServer(Dependencies{
		Resolver: staticResolver{
			lookup: map[string][]net.IP{
				"tunnel.internal": {net.ParseIP("127.0.0.1")},
			},
		},
		IdentityResolver: identityResolver,
		PolicyEngine:     policyEngine,
		Logger:           slog.New(slog.NewTextHandler(io.Discard, nil)),
	}).Handler())
	defer proxyServer.Close()

	proxyURL, err := url.Parse(proxyServer.URL)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	conn, err := net.Dial("tcp", proxyURL.Host)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer conn.Close()

	target := fmt.Sprintf("tunnel.internal:%s", strings.TrimPrefix(upstream.Addr().String(), "127.0.0.1:"))
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		t.Fatalf("Fprintf() error = %v", err)
	}

	reader := bufio.NewReader(conn)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("ReadString() error = %v", err)
	}
	if !strings.Contains(statusLine, "200") {
		t.Fatalf("unexpected status line %q", statusLine)
	}

	for {
		line, readErr := reader.ReadString('\n')
		if readErr != nil {
			t.Fatalf("reading headers: %v", readErr)
		}
		if line == "\r\n" {
			break
		}
	}

	if _, err := conn.Write(append(clientHello, []byte("ping")...)); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	reply := make([]byte, 4)
	if _, err := io.ReadFull(reader, reply); err != nil {
		t.Fatalf("ReadFull() error = %v", err)
	}
	if string(reply) != "pong" {
		t.Fatalf("reply = %q, want %q", string(reply), "pong")
	}

	if identityResolver.calls != 1 {
		t.Fatalf("identity resolver calls = %d, want 1", identityResolver.calls)
	}
	if policyEngine.connectCalls != 1 {
		t.Fatalf("connect policy calls = %d, want 1", policyEngine.connectCalls)
	}

	<-done
}

func TestProxyConnectDeniesBeforeDNSLookup(t *testing.T) {
	dnsCalls := 0
	proxyServer := httptest.NewServer(NewServer(Dependencies{
		Resolver: countingResolver{
			lookup: map[string][]net.IP{"example.com": {net.ParseIP("127.0.0.1")}},
			calls:  &dnsCalls,
		},
		IdentityResolver: staticIdentityResolver{
			identity: &identity.Identity{Labels: map[string]string{"app": "jobs"}},
		},
		PolicyEngine: mustPolicyEngine(t, []config.PolicyConfig{{
			Name: "allow-web",
			IdentitySelector: config.IdentitySelectorConfig{
				MatchLabels: map[string]string{"app": "web"},
			},
			Egress: []config.EgressRuleConfig{{
				FQDN:  "example.com",
				Ports: []int{443},
				TLS:   config.TLSRuleConfig{Mode: "passthrough"},
			}},
		}}),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}).Handler())
	defer proxyServer.Close()

	conn, reader := mustConnectProxy(t, proxyServer.URL, "example.com:443")
	defer conn.Close()

	statusLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("ReadString() error = %v", err)
	}
	if !strings.Contains(statusLine, "403") {
		t.Fatalf("unexpected status line %q", statusLine)
	}
	if dnsCalls != 0 {
		t.Fatalf("dnsCalls = %d, want 0", dnsCalls)
	}
}

func TestProxyConnectionLimiterRejectsSecondConcurrentConnectTunnel(t *testing.T) {
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer upstream.Close()

	upstreamAccepted := make(chan struct{}, 1)
	releaseUpstream := make(chan struct{})
	go func() {
		conn, acceptErr := upstream.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		upstreamAccepted <- struct{}{}
		<-releaseUpstream
	}()

	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	connectionLimiter := NewConnectionLimiter(slog.New(slog.NewTextHandler(io.Discard, nil)), m)
	connectionLimiter.UpdateLimit(1)

	proxyServer := httptest.NewServer(NewServer(Dependencies{
		Resolver: staticResolver{
			lookup: map[string][]net.IP{"tunnel.internal": {net.ParseIP("127.0.0.1")}},
		},
		ConnectionLimiter: connectionLimiter,
		IdentityResolver: staticIdentityResolver{
			identity: &identity.Identity{Name: "default/web", Labels: map[string]string{"app": "web"}},
		},
		PolicyEngine: mustPolicyEngine(t, []config.PolicyConfig{{
			Name: "allow-connect",
			IdentitySelector: config.IdentitySelectorConfig{
				MatchLabels: map[string]string{"app": "web"},
			},
			Egress: []config.EgressRuleConfig{{
				FQDN:  "tunnel.internal",
				Ports: []int{mustPort(t, upstream.Addr().String())},
				TLS:   config.TLSRuleConfig{Mode: "passthrough"},
			}},
		}}),
		Metrics: m,
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
	}).Handler())
	defer proxyServer.Close()

	target := fmt.Sprintf("tunnel.internal:%s", strings.TrimPrefix(upstream.Addr().String(), "127.0.0.1:"))
	conn, reader := mustConnectProxy(t, proxyServer.URL, target)
	defer conn.Close()
	readConnectEstablished(t, reader)

	select {
	case <-upstreamAccepted:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for first tunnel to reach upstream")
	}

	secondConn, err := net.Dial("tcp", strings.TrimPrefix(proxyServer.URL, "http://"))
	if err != nil {
		t.Fatalf("Dial() second error = %v", err)
	}
	defer secondConn.Close()
	if _, err := fmt.Fprintf(secondConn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		t.Fatalf("Fprintf() second error = %v", err)
	}

	secondResp, err := http.ReadResponse(bufio.NewReader(secondConn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("ReadResponse() second error = %v", err)
	}
	defer secondResp.Body.Close()
	if secondResp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second CONNECT status = %d, want %d", secondResp.StatusCode, http.StatusTooManyRequests)
	}

	close(releaseUpstream)

	if got := counterValue(t, reg, "aegis_identity_connection_limit_rejections_total", map[string]string{"protocol": "connect"}); got != 1 {
		t.Fatalf("connect limit rejection metric = %v, want 1", got)
	}
	if got := counterValue(t, reg, "aegis_connect_tunnels_total", map[string]string{
		"mode":   "passthrough",
		"result": "connection_limit_exceeded",
	}); got != 1 {
		t.Fatalf("connect result metric = %v, want 1", got)
	}
	if got := counterValue(t, reg, "aegis_request_decisions_total", map[string]string{
		"protocol": "connect",
		"action":   "deny",
		"policy":   "allow-connect",
		"reason":   "connection_limit_exceeded",
	}); got != 1 {
		t.Fatalf("connect deny decision metric = %v, want 1", got)
	}
}

func TestProxyConnectAuditModeAllowsDeniedTargetsAndRecordsWouldDeny(t *testing.T) {
	clientHello := mustClientHello(t, "tunnel.internal")

	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer upstream.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, acceptErr := upstream.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, len(clientHello)+4)
		_, _ = io.ReadFull(conn, buf)
		_, _ = conn.Write([]byte("pong"))
	}()

	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	proxyServer := httptest.NewServer(NewServer(Dependencies{
		Resolver: staticResolver{
			lookup: map[string][]net.IP{
				"tunnel.internal": {net.ParseIP("127.0.0.1")},
			},
		},
		EnforcementMode: "audit",
		IdentityResolver: staticIdentityResolver{
			identity: &identity.Identity{Name: "default/jobs", Labels: map[string]string{"app": "jobs"}},
		},
		PolicyEngine: mustPolicyEngine(t, []config.PolicyConfig{{
			Name: "allow-web",
			IdentitySelector: config.IdentitySelectorConfig{
				MatchLabels: map[string]string{"app": "web"},
			},
			Egress: []config.EgressRuleConfig{{
				FQDN:  "tunnel.internal",
				Ports: []int{mustPort(t, upstream.Addr().String())},
				TLS:   config.TLSRuleConfig{Mode: "passthrough"},
			}},
		}}),
		Metrics: m,
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
	}).Handler())
	defer proxyServer.Close()

	conn, reader := mustConnectProxy(t, proxyServer.URL, fmt.Sprintf("tunnel.internal:%s", strings.TrimPrefix(upstream.Addr().String(), "127.0.0.1:")))
	defer conn.Close()
	readConnectEstablished(t, reader)

	if _, err := conn.Write(append(clientHello, []byte("ping")...)); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	reply := make([]byte, 4)
	if _, err := io.ReadFull(reader, reply); err != nil {
		t.Fatalf("ReadFull() error = %v", err)
	}
	if string(reply) != "pong" {
		t.Fatalf("reply = %q, want %q", string(reply), "pong")
	}
	if got := counterValue(t, reg, "aegis_request_decisions_total", map[string]string{
		"protocol": "connect",
		"action":   "allow",
		"policy":   "none",
		"reason":   "audit_policy_denied",
	}); got != 1 {
		t.Fatalf("actual decision metric = %v, want 1", got)
	}
	if got := counterValue(t, reg, "aegis_audit_decisions_total", map[string]string{
		"protocol": "connect",
		"action":   "would_deny",
		"identity": "default/jobs",
		"fqdn":     "tunnel.internal",
		"policy":   "none",
		"reason":   "policy_denied",
	}); got != 1 {
		t.Fatalf("audit decision metric = %v, want 1", got)
	}

	<-done
}

func TestProxyConnectBypassPolicyAllowsDeniedTargetsAndRecordsWouldDeny(t *testing.T) {
	clientHello := mustClientHello(t, "denied.internal")

	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer upstream.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, acceptErr := upstream.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, len(clientHello)+4)
		_, _ = io.ReadFull(conn, buf)
		_, _ = conn.Write([]byte("pong"))
	}()

	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	proxyServer := httptest.NewServer(NewServer(Dependencies{
		Resolver: staticResolver{
			lookup: map[string][]net.IP{
				"denied.internal": {net.ParseIP("127.0.0.1")},
			},
		},
		IdentityResolver: staticIdentityResolver{
			identity: &identity.Identity{Name: "default/jobs", Labels: map[string]string{"app": "jobs"}},
		},
		PolicyEngine: mustPolicyEngine(t, []config.PolicyConfig{{
			Name:   "break-glass",
			Bypass: true,
			IdentitySelector: config.IdentitySelectorConfig{
				MatchLabels: map[string]string{"app": "jobs"},
			},
			Egress: []config.EgressRuleConfig{{
				FQDN:  "allowed.internal",
				Ports: []int{mustPort(t, upstream.Addr().String())},
				TLS:   config.TLSRuleConfig{Mode: "mitm"},
				HTTP: &config.HTTPRuleConfig{
					AllowedMethods: []string{"GET"},
					AllowedPaths:   []string{"/allowed"},
				},
			}},
		}}),
		Metrics: m,
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
	}).Handler())
	defer proxyServer.Close()

	conn, reader := mustConnectProxy(t, proxyServer.URL, fmt.Sprintf("denied.internal:%s", strings.TrimPrefix(upstream.Addr().String(), "127.0.0.1:")))
	defer conn.Close()
	readConnectEstablished(t, reader)

	if _, err := conn.Write(append(clientHello, []byte("ping")...)); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	reply := make([]byte, 4)
	if _, err := io.ReadFull(reader, reply); err != nil {
		t.Fatalf("ReadFull() error = %v", err)
	}
	if string(reply) != "pong" {
		t.Fatalf("reply = %q, want %q", string(reply), "pong")
	}
	if got := counterValue(t, reg, "aegis_request_decisions_total", map[string]string{
		"protocol": "connect",
		"action":   "allow",
		"policy":   "break-glass",
		"reason":   "audit_policy_denied",
	}); got != 1 {
		t.Fatalf("actual decision metric = %v, want 1", got)
	}
	if got := counterValue(t, reg, "aegis_audit_decisions_total", map[string]string{
		"protocol": "connect",
		"action":   "would_deny",
		"identity": "default/jobs",
		"fqdn":     "denied.internal",
		"policy":   "break-glass",
		"reason":   "policy_denied",
	}); got != 1 {
		t.Fatalf("audit decision metric = %v, want 1", got)
	}

	<-done
}

func TestProxyConnectBlocksMissingSNI(t *testing.T) {
	clientHello := mustClientHello(t, "")

	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer upstream.Close()

	upstreamRead := make(chan int, 1)
	go func() {
		conn, acceptErr := upstream.Accept()
		if acceptErr != nil {
			upstreamRead <- -1
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		buf := make([]byte, len(clientHello))
		n, _ := conn.Read(buf)
		upstreamRead <- n
	}()

	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	proxyServer := httptest.NewServer(NewServer(Dependencies{
		Resolver: staticResolver{
			lookup: map[string][]net.IP{
				"tunnel.internal": {net.ParseIP("127.0.0.1")},
			},
		},
		IdentityResolver: staticIdentityResolver{
			identity: &identity.Identity{Labels: map[string]string{"app": "web"}},
		},
		PolicyEngine: mustPolicyEngine(t, []config.PolicyConfig{{
			Name:             "allow-all",
			IdentitySelector: config.IdentitySelectorConfig{MatchLabels: map[string]string{}},
			Egress: []config.EgressRuleConfig{{
				FQDN:  "tunnel.internal",
				Ports: []int{mustPort(t, upstream.Addr().String())},
				TLS:   config.TLSRuleConfig{Mode: "passthrough"},
			}},
		}}),
		Metrics: m,
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
	}).Handler())
	defer proxyServer.Close()

	conn, reader := mustConnectProxy(t, proxyServer.URL, fmt.Sprintf("tunnel.internal:%s", strings.TrimPrefix(upstream.Addr().String(), "127.0.0.1:")))
	defer conn.Close()
	readConnectEstablished(t, reader)

	if _, err := conn.Write(clientHello); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	if err == nil {
		t.Fatal("expected tunnel to close for missing sni")
	}

	if n := <-upstreamRead; n != 0 {
		t.Fatalf("upstream read = %d, want 0", n)
	}
}

func TestProxyConnectAuditModeBypassesMissingSNI(t *testing.T) {
	clientHello := mustClientHello(t, "")

	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer upstream.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, acceptErr := upstream.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, len(clientHello)+4)
		_, _ = io.ReadFull(conn, buf)
		_, _ = conn.Write([]byte("pong"))
	}()

	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	proxyServer := httptest.NewServer(NewServer(Dependencies{
		Resolver: staticResolver{
			lookup: map[string][]net.IP{
				"tunnel.internal": {net.ParseIP("127.0.0.1")},
			},
		},
		EnforcementMode: "audit",
		IdentityResolver: staticIdentityResolver{
			identity: &identity.Identity{Labels: map[string]string{"app": "web"}},
		},
		PolicyEngine: mustPolicyEngine(t, []config.PolicyConfig{{
			Name:             "allow-all",
			IdentitySelector: config.IdentitySelectorConfig{MatchLabels: map[string]string{}},
			Egress: []config.EgressRuleConfig{{
				FQDN:  "tunnel.internal",
				Ports: []int{mustPort(t, upstream.Addr().String())},
				TLS:   config.TLSRuleConfig{Mode: "passthrough"},
			}},
		}}),
		Metrics: m,
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
	}).Handler())
	defer proxyServer.Close()

	conn, reader := mustConnectProxy(t, proxyServer.URL, fmt.Sprintf("tunnel.internal:%s", strings.TrimPrefix(upstream.Addr().String(), "127.0.0.1:")))
	defer conn.Close()
	readConnectEstablished(t, reader)

	if _, err := conn.Write(append(clientHello, []byte("ping")...)); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	reply := make([]byte, 4)
	if _, err := io.ReadFull(reader, reply); err != nil {
		t.Fatalf("ReadFull() error = %v", err)
	}
	if string(reply) != "pong" {
		t.Fatalf("reply = %q, want %q", string(reply), "pong")
	}
	if got := counterValue(t, reg, "aegis_request_decisions_total", map[string]string{
		"protocol": "connect",
		"action":   "allow",
		"policy":   "allow-all",
		"reason":   "audit_policy_allowed",
	}); got != 1 {
		t.Fatalf("actual decision metric = %v, want 1", got)
	}

	<-done
}

func TestProxyConnectBlocksSNIMismatch(t *testing.T) {
	clientHello := mustClientHello(t, "other.internal")

	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer upstream.Close()

	upstreamRead := make(chan int, 1)
	go func() {
		conn, acceptErr := upstream.Accept()
		if acceptErr != nil {
			upstreamRead <- -1
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		buf := make([]byte, len(clientHello))
		n, _ := conn.Read(buf)
		upstreamRead <- n
	}()

	proxyServer := httptest.NewServer(NewServer(Dependencies{
		Resolver: staticResolver{
			lookup: map[string][]net.IP{
				"tunnel.internal": {net.ParseIP("127.0.0.1")},
			},
		},
		IdentityResolver: staticIdentityResolver{
			identity: &identity.Identity{Labels: map[string]string{"app": "web"}},
		},
		PolicyEngine: mustPolicyEngine(t, []config.PolicyConfig{{
			Name:             "allow-all",
			IdentitySelector: config.IdentitySelectorConfig{MatchLabels: map[string]string{}},
			Egress: []config.EgressRuleConfig{{
				FQDN:  "tunnel.internal",
				Ports: []int{mustPort(t, upstream.Addr().String())},
				TLS:   config.TLSRuleConfig{Mode: "passthrough"},
			}},
		}}),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}).Handler())
	defer proxyServer.Close()

	conn, reader := mustConnectProxy(t, proxyServer.URL, fmt.Sprintf("tunnel.internal:%s", strings.TrimPrefix(upstream.Addr().String(), "127.0.0.1:")))
	defer conn.Close()
	readConnectEstablished(t, reader)

	if _, err := conn.Write(clientHello); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	if err == nil {
		t.Fatal("expected tunnel to close for sni mismatch")
	}

	if n := <-upstreamRead; n != 0 {
		t.Fatalf("upstream read = %d, want 0", n)
	}
}

func TestProxyConnectBlocksResolvedPrivateAddress(t *testing.T) {
	dnsCalls := 0
	proxyServer := httptest.NewServer(NewServer(Dependencies{
		Resolver: countingResolver{
			lookup: map[string][]net.IP{"example.com": {net.ParseIP("127.0.0.1")}},
			calls:  &dnsCalls,
		},
		DestinationGuard: mustDestinationGuard(t, nil, nil),
		IdentityResolver: staticIdentityResolver{
			identity: &identity.Identity{Labels: map[string]string{"app": "web"}},
		},
		PolicyEngine: mustPolicyEngine(t, []config.PolicyConfig{{
			Name:             "allow-all",
			IdentitySelector: config.IdentitySelectorConfig{MatchLabels: map[string]string{}},
			Egress: []config.EgressRuleConfig{{
				FQDN:  "example.com",
				Ports: []int{443},
				TLS:   config.TLSRuleConfig{Mode: "passthrough"},
			}},
		}}),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}).Handler())
	defer proxyServer.Close()

	conn, reader := mustConnectProxy(t, proxyServer.URL, "example.com:443")
	defer conn.Close()

	statusLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("ReadString() error = %v", err)
	}
	if !strings.Contains(statusLine, "403") {
		t.Fatalf("unexpected status line %q", statusLine)
	}
	if dnsCalls != 1 {
		t.Fatalf("dnsCalls = %d, want 1", dnsCalls)
	}
}

type staticResolver struct {
	lookup map[string][]net.IP
}

func (s staticResolver) LookupNetIP(_ context.Context, host string) ([]net.IP, error) {
	ips, ok := s.lookup[host]
	if !ok {
		return nil, fmt.Errorf("host not found: %s", host)
	}
	return ips, nil
}

type countingResolver struct {
	lookup map[string][]net.IP
	calls  *int
}

func (r countingResolver) LookupNetIP(_ context.Context, host string) ([]net.IP, error) {
	if r.calls != nil {
		*r.calls = *r.calls + 1
	}
	ips, ok := r.lookup[host]
	if !ok {
		return nil, fmt.Errorf("host not found: %s", host)
	}
	return ips, nil
}

type staticIdentityResolver struct {
	identity *identity.Identity
	err      error
}

func (r staticIdentityResolver) Resolve(net.IP) (*identity.Identity, error) {
	if r.err != nil {
		return nil, r.err
	}
	if r.identity == nil {
		return nil, nil
	}

	cloned := &identity.Identity{
		Source:   r.identity.Source,
		Provider: r.identity.Provider,
		Name:     r.identity.Name,
		Labels:   make(map[string]string, len(r.identity.Labels)),
	}
	for key, value := range r.identity.Labels {
		cloned.Labels[key] = value
	}
	if strings.TrimSpace(cloned.Source) == "" {
		cloned.Source = "kubernetes"
	}
	if cloned.Source == "kubernetes" {
		if strings.TrimSpace(cloned.Provider) == "" {
			cloned.Provider = testPolicyDiscoveryName
		}
		if _, ok := cloned.Labels["kubernetes.io/namespace"]; !ok {
			cloned.Labels["kubernetes.io/namespace"] = testPolicyNamespace
		}
	}

	return cloned, nil
}

type spyIdentityResolver struct {
	calls   int
	resolve func(net.IP) (*identity.Identity, error)
}

func (r *spyIdentityResolver) Resolve(ip net.IP) (*identity.Identity, error) {
	r.calls++
	if r.resolve == nil {
		return nil, nil
	}
	return r.resolve(ip)
}

type policyEngineStub struct {
	calls           int
	connectCalls    int
	evaluate        func(id *identity.Identity, sourceIP netip.Addr, fqdn string, port int, method string, reqPath string) *policy.Decision
	evaluateConnect func(id *identity.Identity, sourceIP netip.Addr, fqdn string, port int) *policy.Decision
}

func (p *policyEngineStub) Evaluate(id *identity.Identity, sourceIP netip.Addr, fqdn string, port int, method string, reqPath string) *policy.Decision {
	p.calls++
	if p.evaluate == nil {
		return &policy.Decision{}
	}
	return p.evaluate(id, sourceIP, fqdn, port, method, reqPath)
}

func (p *policyEngineStub) EvaluateConnect(id *identity.Identity, sourceIP netip.Addr, fqdn string, port int) *policy.Decision {
	p.connectCalls++
	if p.evaluateConnect == nil {
		return &policy.Decision{}
	}
	return p.evaluateConnect(id, sourceIP, fqdn, port)
}

func mustPolicyEngine(t *testing.T, cfgs []config.PolicyConfig) *policy.Engine {
	t.Helper()

	normalized := make([]config.PolicyConfig, len(cfgs))
	for i, cfg := range cfgs {
		normalized[i] = cfg
		if normalized[i].Subjects.Kubernetes != nil || normalized[i].Subjects.EC2 != nil || len(normalized[i].Subjects.CIDRs) > 0 {
			continue
		}
		normalized[i].Subjects = config.PolicySubjectsConfig{
			Kubernetes: &config.KubernetesSubjectConfig{
				DiscoveryNames: []string{testPolicyDiscoveryName},
				Namespaces:     []string{testPolicyNamespace},
				MatchLabels:    cloneConfigLabels(cfg.IdentitySelector.MatchLabels),
			},
		}
	}

	engine, err := policy.NewEngine(normalized)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	return engine
}

func cloneConfigLabels(labels map[string]string) map[string]string {
	if len(labels) == 0 {
		return map[string]string{}
	}

	cloned := make(map[string]string, len(labels))
	for key, value := range labels {
		cloned[key] = value
	}
	return cloned
}

func proxiedRequest(proxyAddr string, method string, targetURL string, body io.Reader) (*http.Response, error) {
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: func(*http.Request) (*url.URL, error) {
				return url.Parse(proxyAddr)
			},
		},
	}

	req, err := http.NewRequest(method, targetURL, body)
	if err != nil {
		return nil, err
	}

	return client.Do(req)
}

func hostPortSuffix(hostport string) string {
	return hostport[strings.LastIndex(hostport, ":"):]
}

func mustConnectProxy(t *testing.T, proxyAddr string, target string) (net.Conn, *bufio.Reader) {
	t.Helper()

	proxyURL, err := url.Parse(proxyAddr)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	conn, err := net.Dial("tcp", proxyURL.Host)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}

	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		conn.Close()
		t.Fatalf("Fprintf() error = %v", err)
	}

	return conn, bufio.NewReader(conn)
}

func readConnectEstablished(t *testing.T, reader *bufio.Reader) {
	t.Helper()

	statusLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("ReadString() error = %v", err)
	}
	if !strings.Contains(statusLine, "200") {
		t.Fatalf("unexpected status line %q", statusLine)
	}

	for {
		line, readErr := reader.ReadString('\n')
		if readErr != nil {
			t.Fatalf("reading headers: %v", readErr)
		}
		if line == "\r\n" {
			return
		}
	}
}

func mustPort(t *testing.T, hostport string) int {
	t.Helper()

	_, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		t.Fatalf("SplitHostPort() error = %v", err)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("Atoi() error = %v", err)
	}

	return port
}

func mustDestinationGuard(t *testing.T, allowedHostPatterns []string, allowedCIDRs []string) *DestinationGuard {
	t.Helper()

	guard, err := NewDestinationGuard(allowedHostPatterns, allowedCIDRs, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewDestinationGuard() error = %v", err)
	}
	return guard
}

func histogramSampleCount(t *testing.T, reg *prometheus.Registry, name string, labels map[string]string) uint64 {
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
			if !hasPrometheusLabels(metric.GetLabel(), labels) {
				continue
			}
			if metric.GetHistogram() == nil {
				t.Fatalf("metric %q is not a histogram", name)
			}
			return metric.GetHistogram().GetSampleCount()
		}
	}

	t.Fatalf("metric %q with labels %#v not found", name, labels)
	return 0
}

func hasPrometheusLabels(pairs []*dto.LabelPair, want map[string]string) bool {
	if len(pairs) != len(want) {
		return false
	}
	for _, pair := range pairs {
		if want[pair.GetName()] != pair.GetValue() {
			return false
		}
	}
	return true
}
