package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/moolen/aegis/internal/config"
	"github.com/moolen/aegis/internal/identity"
	"github.com/moolen/aegis/internal/metrics"
)

func TestMITMServerAdvertisesHTTP2(t *testing.T) {
	server := newMITMHTTPServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	if server.TLSConfig == nil {
		t.Fatal("expected TLS config")
	}
	if !slices.Equal(server.TLSConfig.NextProtos, []string{"h2", "http/1.1"}) {
		t.Fatalf("next protos = %#v, want h2 + http/1.1", server.TLSConfig.NextProtos)
	}
}

func TestMITMPathSupportsHTTP2ClientMultiplexing(t *testing.T) {
	proxyServer, targetURL, roots, reg := newHTTP2MITMTestProxy(t)

	client := newHTTP2ProxyClient(t, proxyServer.URL, roots)

	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("warmup Get() error = %v", err)
	}
	resp.Body.Close()
	if resp.ProtoMajor != 2 {
		t.Fatalf("warmup proto major = %d, want 2", resp.ProtoMajor)
	}

	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := client.Get(targetURL)
			if err != nil {
				errs <- err
				return
			}
			defer resp.Body.Close()
			if resp.ProtoMajor != 2 {
				errs <- fmt.Errorf("proto major = %d, want 2", resp.ProtoMajor)
				return
			}
			if resp.StatusCode != http.StatusNoContent {
				errs <- fmt.Errorf("status = %d, want 204", resp.StatusCode)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}

	if got := counterValue(t, reg, "aegis_connect_tunnels_total", map[string]string{"mode": "mitm", "result": "established"}); got != 1 {
		t.Fatalf("connect tunnel metric = %v, want 1", got)
	}
}

func TestMITMPathForwardsHTTP2ResponseTrailers(t *testing.T) {
	proxyServer, targetURL, roots, _ := newHTTP2MITMTestProxyWithHandler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Trailer", "X-Upstream-Trailer")
		w.WriteHeader(http.StatusOK)
		if _, err := io.WriteString(w, "ok"); err != nil {
			t.Fatalf("WriteString() error = %v", err)
		}
		w.Header().Set("X-Upstream-Trailer", "done")
	}))

	client := newHTTP2ProxyClient(t, proxyServer.URL, roots)
	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	if string(body) != "ok" {
		t.Fatalf("body = %q, want %q", string(body), "ok")
	}
	if resp.ProtoMajor != 2 {
		t.Fatalf("proto major = %d, want 2", resp.ProtoMajor)
	}
	if got := resp.Trailer.Get("X-Upstream-Trailer"); got != "done" {
		t.Fatalf("trailer = %q, want %q", got, "done")
	}
}

func TestMITMPathForwardsUndeclaredHTTP2ResponseTrailers(t *testing.T) {
	proxyServer, targetURL, roots, _ := newHTTP2MITMTestProxyWithHandler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := io.WriteString(w, "ok"); err != nil {
			t.Fatalf("WriteString() error = %v", err)
		}
		w.Header().Set(http.TrailerPrefix+"X-Upstream-Late", "late")
	}))

	client := newHTTP2ProxyClient(t, proxyServer.URL, roots)
	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	if string(body) != "ok" {
		t.Fatalf("body = %q, want %q", string(body), "ok")
	}
	if resp.ProtoMajor != 2 {
		t.Fatalf("proto major = %d, want 2", resp.ProtoMajor)
	}
	if got := resp.Trailer.Get("X-Upstream-Late"); got != "late" {
		t.Fatalf("trailer = %q, want %q", got, "late")
	}
}

func TestMITMHTTP2DeniesOneStreamWithoutBreakingOthers(t *testing.T) {
	allowedStarted := make(chan struct{})
	releaseAllowed := make(chan struct{})
	var allowedStartedOnce sync.Once
	var allowedCount atomic.Int32
	proxyServer, targetURL, roots, reg, clientConnCount := newHTTP2MITMTestProxyWithConnCounter(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/allowed":
			currentAllowed := allowedCount.Add(1)
			if currentAllowed >= 2 {
				allowedStartedOnce.Do(func() { close(allowedStarted) })
				<-releaseAllowed
			}
			w.WriteHeader(http.StatusOK)
			if _, err := io.WriteString(w, "allowed-body"); err != nil {
				t.Fatalf("WriteString() error = %v", err)
			}
		case "/denied":
			t.Fatalf("unexpected upstream call for denied path")
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	}))

	baseURL, err := url.Parse(targetURL)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	allowedURL := *baseURL
	allowedURL.Path = "/allowed"
	deniedURL := *baseURL
	deniedURL.Path = "/denied"

	client := newHTTP2ProxyClient(t, proxyServer.URL, roots)

	warmup, err := client.Get(allowedURL.String())
	if err != nil {
		t.Fatalf("warmup Get() error = %v", err)
	}
	warmup.Body.Close()
	if warmup.ProtoMajor != 2 {
		t.Fatalf("warmup proto major = %d, want 2", warmup.ProtoMajor)
	}

	type allowedResult struct {
		status int
		proto  int
		body   string
	}
	type deniedResult struct {
		status int
		proto  int
	}

	allowedDone := make(chan allowedResult, 1)
	allowedErrs := make(chan error, 1)
	go func() {
		resp, err := client.Get(allowedURL.String())
		if err != nil {
			allowedErrs <- fmt.Errorf("Get(/allowed) error = %w", err)
			return
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			allowedErrs <- fmt.Errorf("ReadAll(/allowed) error = %w", err)
			return
		}

		allowedDone <- allowedResult{
			status: resp.StatusCode,
			proto:  resp.ProtoMajor,
			body:   string(body),
		}
	}()

	deniedDone := make(chan deniedResult, 1)
	deniedErrs := make(chan error, 1)

	select {
	case err := <-allowedErrs:
		t.Fatal(err)
	case <-allowedStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for /allowed to reach upstream")
	}

	go func() {
		resp, err := client.Get(deniedURL.String())
		if err != nil {
			deniedErrs <- fmt.Errorf("Get(/denied) error = %w", err)
			return
		}
		resp.Body.Close()
		deniedDone <- deniedResult{
			status: resp.StatusCode,
			proto:  resp.ProtoMajor,
		}
	}()

	var denied deniedResult
	select {
	case err := <-deniedErrs:
		close(releaseAllowed)
		t.Fatal(err)
	case denied = <-deniedDone:
	case <-time.After(2 * time.Second):
		close(releaseAllowed)
		t.Fatal("timed out waiting for /denied while /allowed was still in flight")
	}

	close(releaseAllowed)

	var allowed allowedResult
	select {
	case err := <-allowedErrs:
		t.Fatal(err)
	case allowed = <-allowedDone:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for /allowed response")
	}

	if denied.proto != 2 {
		t.Fatalf("/denied proto major = %d, want 2", denied.proto)
	}
	if denied.status != http.StatusForbidden {
		t.Fatalf("/denied status = %d, want %d", denied.status, http.StatusForbidden)
	}
	if allowed.proto != 2 {
		t.Fatalf("/allowed proto major = %d, want 2", allowed.proto)
	}
	if allowed.status != http.StatusOK {
		t.Fatalf("/allowed status = %d, want %d", allowed.status, http.StatusOK)
	}
	if allowed.body != "allowed-body" {
		t.Fatalf("/allowed body = %q, want %q", allowed.body, "allowed-body")
	}
	if got := allowedCount.Load(); got != 2 {
		t.Fatalf("/allowed upstream hits = %d, want 2 (warmup + one in-flight request)", got)
	}
	if got := counterValue(t, reg, "aegis_connect_tunnels_total", map[string]string{"mode": "mitm", "result": "established"}); got != 1 {
		t.Fatalf("connect tunnel metric = %v, want 1", got)
	}
	if got := clientConnCount.Load(); got != 1 {
		t.Fatalf("proxy client connections = %d, want 1", got)
	}
}

func TestMITMHTTP2PathIdleTimeoutClosesConnectionAfterRequest(t *testing.T) {
	proxyServer, targetURL, roots, reg := newHTTP2MITMTestProxyWithOptions(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), 50*time.Millisecond)

	client := newHTTP2ProxyClient(t, proxyServer.URL, roots)
	first, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("first Get() error = %v", err)
	}
	first.Body.Close()
	if first.ProtoMajor != 2 {
		t.Fatalf("first proto major = %d, want 2", first.ProtoMajor)
	}

	time.Sleep(200 * time.Millisecond)

	second, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("second Get() error = %v", err)
	}
	second.Body.Close()
	if second.ProtoMajor != 2 {
		t.Fatalf("second proto major = %d, want 2", second.ProtoMajor)
	}

	if got := counterValue(t, reg, "aegis_connect_tunnels_total", map[string]string{"mode": "mitm", "result": "established"}); got != 2 {
		t.Fatalf("connect tunnel metric = %v, want 2", got)
	}
}

func newHTTP2MITMTestProxy(t *testing.T) (*httptest.Server, string, *x509.CertPool, *prometheus.Registry) {
	t.Helper()
	return newHTTP2MITMTestProxyWithOptions(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(25 * time.Millisecond)
		w.WriteHeader(http.StatusNoContent)
	}), 0)
}

func newHTTP2MITMTestProxyWithHandler(t *testing.T, upstreamHandler http.Handler) (*httptest.Server, string, *x509.CertPool, *prometheus.Registry) {
	t.Helper()
	proxyServer, targetURL, roots, reg, _ := newHTTP2MITMTestProxyWithConnCounter(t, upstreamHandler)
	return proxyServer, targetURL, roots, reg
}

func newHTTP2MITMTestProxyWithOptions(t *testing.T, upstreamHandler http.Handler, idleTimeout time.Duration) (*httptest.Server, string, *x509.CertPool, *prometheus.Registry) {
	t.Helper()
	proxyServer, targetURL, roots, reg, _ := newHTTP2MITMTestProxyWithOptionsAndConnCounter(t, upstreamHandler, idleTimeout)
	return proxyServer, targetURL, roots, reg
}

func newHTTP2MITMTestProxyWithConnCounter(t *testing.T, upstreamHandler http.Handler) (*httptest.Server, string, *x509.CertPool, *prometheus.Registry, *atomic.Int32) {
	t.Helper()
	return newHTTP2MITMTestProxyWithOptionsAndConnCounter(t, upstreamHandler, 0)
}

func newHTTP2MITMTestProxyWithOptionsAndConnCounter(t *testing.T, upstreamHandler http.Handler, idleTimeout time.Duration) (*httptest.Server, string, *x509.CertPool, *prometheus.Registry, *atomic.Int32) {
	t.Helper()

	ca := newMITMTestCA(t)
	mitmEngine, err := NewMITMEngine(ca.certificate, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewMITMEngine() error = %v", err)
	}

	upstream := httptest.NewUnstartedServer(upstreamHandler)
	upstream.EnableHTTP2 = true
	upstream.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{ca.issueServerCertificate(t, "example.test")},
	}
	upstream.StartTLS()

	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	var clientConnCount atomic.Int32
	proxyServer := httptest.NewUnstartedServer(NewServer(Dependencies{
		Resolver: staticResolver{
			lookup: map[string][]net.IP{"example.test": {net.ParseIP("127.0.0.1")}},
		},
		ConnectionIdleTimeout: idleTimeout,
		IdentityResolver: staticIdentityResolver{
			identity: &identity.Identity{Labels: map[string]string{"app": "web"}},
		},
		PolicyEngine: mustPolicyEngine(t, []config.PolicyConfig{{
			Name: "allow-tls-http2",
			IdentitySelector: config.IdentitySelectorConfig{
				MatchLabels: map[string]string{"app": "web"},
			},
			Egress: []config.EgressRuleConfig{{
				FQDN:  "example.test",
				Ports: []int{mustPort(t, upstream.Listener.Addr().String())},
				TLS:   config.TLSRuleConfig{Mode: "mitm"},
				HTTP: &config.HTTPRuleConfig{
					AllowedMethods: []string{"GET"},
					AllowedPaths:   []string{"/allowed"},
				},
			}},
		}}),
		MITM: mitmEngine,
		UpstreamTLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    ca.roots,
		},
		Metrics: m,
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
	}).Handler())
	proxyServer.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			clientConnCount.Add(1)
		}
	}
	proxyServer.Start()
	t.Cleanup(func() {
		proxyServer.Close()
		upstream.Close()
	})

	targetURL := fmt.Sprintf("https://example.test:%d/allowed", mustPort(t, upstream.Listener.Addr().String()))
	return proxyServer, targetURL, ca.roots, reg, &clientConnCount
}

func newHTTP2ProxyClient(t *testing.T, proxyAddr string, roots *x509.CertPool) *http.Client {
	t.Helper()

	proxyURL, err := url.Parse(proxyAddr)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    roots,
		},
		ForceAttemptHTTP2: true,
	}
	t.Cleanup(transport.CloseIdleConnections)

	return &http.Client{Transport: transport}
}
