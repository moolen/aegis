package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/moolen/aegis/internal/config"
	"github.com/moolen/aegis/internal/identity"
	"github.com/moolen/aegis/internal/metrics"
	"github.com/moolen/aegis/internal/policy"
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

func TestProxyEstablishesConnectTunnel(t *testing.T) {
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

		buf := make([]byte, 4)
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

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	reply := make([]byte, 4)
	if _, err := io.ReadFull(reader, reply); err != nil {
		t.Fatalf("ReadFull() error = %v", err)
	}
	if string(reply) != "pong" {
		t.Fatalf("reply = %q, want %q", string(reply), "pong")
	}

	<-done
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
	return r.identity, nil
}

func mustPolicyEngine(t *testing.T, cfgs []config.PolicyConfig) *policy.Engine {
	t.Helper()

	engine, err := policy.NewEngine(cfgs)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	return engine
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
