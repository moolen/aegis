package proxy

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/moolen/aegis/internal/config"
	"github.com/moolen/aegis/internal/identity"
	"github.com/moolen/aegis/internal/metrics"
)

func TestProxyConnectMITMAllowsHTTPRequest(t *testing.T) {
	ca := newMITMTestCA(t)
	mitmEngine, err := NewMITMEngine(ca.certificate, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewMITMEngine() error = %v", err)
	}

	var upstreamHits atomic.Int32
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		if r.Method != http.MethodGet {
			t.Fatalf("method = %q, want %q", r.Method, http.MethodGet)
		}
		if r.URL.Path != "/allowed" {
			t.Fatalf("path = %q, want %q", r.URL.Path, "/allowed")
		}
		if r.Host != "tunnel.internal" {
			t.Fatalf("host = %q, want %q", r.Host, "tunnel.internal")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	upstream.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{ca.issueServerCertificate(t, "tunnel.internal")},
	}
	upstream.StartTLS()
	defer upstream.Close()

	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	proxyServer := httptest.NewServer(NewServer(Dependencies{
		Resolver: staticResolver{
			lookup: map[string][]net.IP{"tunnel.internal": {net.ParseIP("127.0.0.1")}},
		},
		IdentityResolver: staticIdentityResolver{
			identity: &identity.Identity{Labels: map[string]string{"app": "web"}},
		},
		PolicyEngine: mustPolicyEngine(t, []config.PolicyConfig{{
			Name: "allow-tls-http",
			IdentitySelector: config.IdentitySelectorConfig{
				MatchLabels: map[string]string{"app": "web"},
			},
			Egress: []config.EgressRuleConfig{{
				FQDN:  "tunnel.internal",
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
	defer proxyServer.Close()

	clientTLSConn := mustMITMConnectClient(t, proxyServer.URL, fmt.Sprintf("tunnel.internal:%d", mustPort(t, upstream.Listener.Addr().String())), ca.roots)
	defer clientTLSConn.Close()

	if _, err := fmt.Fprintf(clientTLSConn, "GET /allowed HTTP/1.1\r\nHost: tunnel.internal\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatalf("Fprintf() error = %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(clientTLSConn), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("ReadResponse() error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}
	if upstreamHits.Load() != 1 {
		t.Fatalf("upstreamHits = %d, want 1", upstreamHits.Load())
	}
	if got := counterValue(t, reg, "aegis_connect_tunnels_total", map[string]string{"mode": "mitm", "result": "established"}); got != 1 {
		t.Fatalf("connect tunnel metric = %v, want 1", got)
	}
	if got := counterValue(t, reg, "aegis_mitm_certificates_total", map[string]string{"result": "issued"}); got != 1 {
		t.Fatalf("mitm certificate metric = %v, want 1", got)
	}
}

func TestProxyConnectMITMReusesUpstreamConnectionAcrossClientTunnels(t *testing.T) {
	ca := newMITMTestCA(t)
	mitmEngine, err := NewMITMEngine(ca.certificate, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewMITMEngine() error = %v", err)
	}

	var upstreamConnections atomic.Int32
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	upstream.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			upstreamConnections.Add(1)
		}
	}
	upstream.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{ca.issueServerCertificate(t, "tunnel.internal")},
	}
	upstream.StartTLS()
	defer upstream.Close()

	proxyServer := httptest.NewServer(NewServer(Dependencies{
		Resolver: staticResolver{
			lookup: map[string][]net.IP{"tunnel.internal": {net.ParseIP("127.0.0.1")}},
		},
		IdentityResolver: staticIdentityResolver{
			identity: &identity.Identity{Labels: map[string]string{"app": "web"}},
		},
		PolicyEngine: mustPolicyEngine(t, []config.PolicyConfig{{
			Name: "allow-tls-http",
			IdentitySelector: config.IdentitySelectorConfig{
				MatchLabels: map[string]string{"app": "web"},
			},
			Egress: []config.EgressRuleConfig{{
				FQDN:  "tunnel.internal",
				Ports: []int{mustPort(t, upstream.Listener.Addr().String())},
				TLS:   config.TLSRuleConfig{Mode: "mitm"},
				HTTP: &config.HTTPRuleConfig{
					AllowedMethods: []string{"GET"},
					AllowedPaths:   []string{"/*"},
				},
			}},
		}}),
		MITM: mitmEngine,
		UpstreamTLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    ca.roots,
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}).Handler())
	defer proxyServer.Close()

	target := fmt.Sprintf("tunnel.internal:%d", mustPort(t, upstream.Listener.Addr().String()))
	for i := 0; i < 3; i++ {
		clientTLSConn := mustMITMConnectClient(t, proxyServer.URL, target, ca.roots)
		if _, err := fmt.Fprintf(clientTLSConn, "GET /reuse HTTP/1.1\r\nHost: tunnel.internal\r\nConnection: close\r\n\r\n"); err != nil {
			clientTLSConn.Close()
			t.Fatalf("Fprintf() error = %v", err)
		}

		resp, err := http.ReadResponse(bufio.NewReader(clientTLSConn), &http.Request{Method: http.MethodGet})
		if err != nil {
			clientTLSConn.Close()
			t.Fatalf("ReadResponse() error = %v", err)
		}
		resp.Body.Close()
		clientTLSConn.Close()

		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
		}
	}

	if got := upstreamConnections.Load(); got != 1 {
		t.Fatalf("upstreamConnections = %d, want 1", got)
	}
}

func TestProxyConnectMITMStripsHopByHopResponseHeaders(t *testing.T) {
	ca := newMITMTestCA(t)
	mitmEngine, err := NewMITMEngine(ca.certificate, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewMITMEngine() error = %v", err)
	}

	upstream, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{ca.issueServerCertificate(t, "tunnel.internal")},
	})
	if err != nil {
		t.Fatalf("tls.Listen() error = %v", err)
	}
	defer upstream.Close()

	upstreamDone := make(chan struct{})
	go func() {
		defer close(upstreamDone)
		conn, acceptErr := upstream.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()

		req, readErr := http.ReadRequest(bufio.NewReader(conn))
		if readErr != nil {
			return
		}
		req.Body.Close()
		_, _ = io.WriteString(conn, "HTTP/1.1 204 No Content\r\nConnection: Foo\r\nFoo: remove-me\r\nX-End-To-End: keep-me\r\nContent-Length: 0\r\n\r\n")
	}()

	proxyServer := httptest.NewServer(NewServer(Dependencies{
		Resolver: staticResolver{
			lookup: map[string][]net.IP{"tunnel.internal": {net.ParseIP("127.0.0.1")}},
		},
		IdentityResolver: staticIdentityResolver{
			identity: &identity.Identity{Labels: map[string]string{"app": "web"}},
		},
		PolicyEngine: mustPolicyEngine(t, []config.PolicyConfig{{
			Name: "allow-tls-http",
			IdentitySelector: config.IdentitySelectorConfig{
				MatchLabels: map[string]string{"app": "web"},
			},
			Egress: []config.EgressRuleConfig{{
				FQDN:  "tunnel.internal",
				Ports: []int{mustPort(t, upstream.Addr().String())},
				TLS:   config.TLSRuleConfig{Mode: "mitm"},
				HTTP: &config.HTTPRuleConfig{
					AllowedMethods: []string{"GET"},
					AllowedPaths:   []string{"/*"},
				},
			}},
		}}),
		MITM: mitmEngine,
		UpstreamTLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    ca.roots,
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}).Handler())
	defer proxyServer.Close()

	clientTLSConn := mustMITMConnectClient(t, proxyServer.URL, fmt.Sprintf("tunnel.internal:%d", mustPort(t, upstream.Addr().String())), ca.roots)
	defer clientTLSConn.Close()

	if _, err := fmt.Fprintf(clientTLSConn, "GET / HTTP/1.1\r\nHost: tunnel.internal\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatalf("Fprintf() error = %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(clientTLSConn), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("ReadResponse() error = %v", err)
	}
	defer resp.Body.Close()

	if got := resp.Header.Get("Connection"); got != "" {
		t.Fatalf("Connection header = %q, want empty", got)
	}
	if got := resp.Header.Get("Foo"); got != "" {
		t.Fatalf("Foo header = %q, want empty", got)
	}
	if got := resp.Header.Get("X-End-To-End"); got != "keep-me" {
		t.Fatalf("X-End-To-End header = %q, want keep-me", got)
	}

	<-upstreamDone
}

func TestProxyConnectMITMIdleTimeoutClosesClientSession(t *testing.T) {
	ca := newMITMTestCA(t)
	mitmEngine, err := NewMITMEngine(ca.certificate, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewMITMEngine() error = %v", err)
	}

	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	upstream.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{ca.issueServerCertificate(t, "tunnel.internal")},
	}
	upstream.StartTLS()
	defer upstream.Close()

	proxyServer := httptest.NewServer(NewServer(Dependencies{
		Resolver: staticResolver{
			lookup: map[string][]net.IP{"tunnel.internal": {net.ParseIP("127.0.0.1")}},
		},
		ConnectionIdleTimeout: 50 * time.Millisecond,
		IdentityResolver: staticIdentityResolver{
			identity: &identity.Identity{Labels: map[string]string{"app": "web"}},
		},
		PolicyEngine: mustPolicyEngine(t, []config.PolicyConfig{{
			Name: "allow-tls-http",
			IdentitySelector: config.IdentitySelectorConfig{
				MatchLabels: map[string]string{"app": "web"},
			},
			Egress: []config.EgressRuleConfig{{
				FQDN:  "tunnel.internal",
				Ports: []int{mustPort(t, upstream.Listener.Addr().String())},
				TLS:   config.TLSRuleConfig{Mode: "mitm"},
				HTTP: &config.HTTPRuleConfig{
					AllowedMethods: []string{"GET"},
					AllowedPaths:   []string{"/*"},
				},
			}},
		}}),
		MITM: mitmEngine,
		UpstreamTLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    ca.roots,
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}).Handler())
	defer proxyServer.Close()

	clientTLSConn := mustMITMConnectClient(t, proxyServer.URL, fmt.Sprintf("tunnel.internal:%d", mustPort(t, upstream.Listener.Addr().String())), ca.roots)
	defer clientTLSConn.Close()

	_ = clientTLSConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 1)
	if _, err := clientTLSConn.Read(buf); err == nil {
		t.Fatal("expected mitm client session to close after idle timeout")
	}
}

func TestMITMEngineSupportsAdditionalCAs(t *testing.T) {
	primary := newMITMTestCA(t)
	secondary := newMITMTestCA(t)

	engine, err := NewMITMEngine(primary.certificate, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewMITMEngine() error = %v", err)
	}
	if err := engine.AddAdditionalCA(secondary.certificate); err != nil {
		t.Fatalf("AddAdditionalCA() error = %v", err)
	}

	fingerprints := engine.Fingerprints()
	if len(fingerprints) != 2 {
		t.Fatalf("fingerprints = %#v, want primary and secondary fingerprints", fingerprints)
	}
	if fingerprints[0] == fingerprints[1] {
		t.Fatalf("fingerprints = %#v, want distinct fingerprints", fingerprints)
	}
}

func TestMITMEngineAlwaysIssuesWithPrimaryCA(t *testing.T) {
	primary := newMITMTestCA(t)
	companion := newMITMTestCA(t)

	engine, err := NewMITMEngine(primary.certificate, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewMITMEngine() error = %v", err)
	}
	if err := engine.AddAdditionalCA(companion.certificate); err != nil {
		t.Fatalf("AddAdditionalCA() error = %v", err)
	}

	cert, result, err := engine.CertificateForSNI("example.internal")
	if err != nil {
		t.Fatalf("CertificateForSNI() error = %v", err)
	}
	if result != "issued" {
		t.Fatalf("result = %q, want %q", result, "issued")
	}
	if cert.Leaf == nil {
		t.Fatal("expected leaf certificate to be parsed")
	}
	if got, want := engine.issuer.role, mitmCAIssuerRole; got != want {
		t.Fatalf("issuer role = %q, want %q", got, want)
	}
	if engine.issuer.signer == nil {
		t.Fatal("expected issuer signer material to be retained")
	}
	primaryLeaf, _, err := parseMITMCA(primary.certificate)
	if err != nil {
		t.Fatalf("parseMITMCA(primary) error = %v", err)
	}
	if err := cert.Leaf.CheckSignatureFrom(primaryLeaf); err != nil {
		t.Fatalf("CheckSignatureFrom(primary) error = %v", err)
	}
	if err := cert.Leaf.CheckSignatureFrom(companion.leaf); err == nil {
		t.Fatal("expected generated leaf to not verify against companion CA")
	}
	if got, want := string(cert.Leaf.AuthorityKeyId), string(primaryLeaf.SubjectKeyId); got != want {
		t.Fatalf("AuthorityKeyId = %x, want %x", cert.Leaf.AuthorityKeyId, primaryLeaf.SubjectKeyId)
	}
}

func TestMITMEngineReportsIssuerAndCompanionFingerprints(t *testing.T) {
	primary := newMITMTestCA(t)
	companionA := newMITMTestCA(t)
	companionB := newMITMTestCA(t)

	engine, err := NewMITMEngine(primary.certificate, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewMITMEngine() error = %v", err)
	}
	if err := engine.AddAdditionalCA(companionA.certificate); err != nil {
		t.Fatalf("AddAdditionalCA(companionA) error = %v", err)
	}
	if err := engine.AddAdditionalCA(companionB.certificate); err != nil {
		t.Fatalf("AddAdditionalCA(companionB) error = %v", err)
	}
	if len(engine.companions) != 2 {
		t.Fatalf("companions = %#v, want two runtime companion records", engine.companions)
	}
	for i, companion := range engine.companions {
		if got, want := companion.role, mitmCACompanionRole; got != want {
			t.Fatalf("companions[%d].role = %q, want %q", i, got, want)
		}
		if companion.signer != nil {
			t.Fatalf("companions[%d].signer = %#v, want nil signer material", i, companion.signer)
		}
		if companion.leaf == nil {
			t.Fatalf("companions[%d].leaf = nil, want retained parsed leaf", i)
		}
	}

	_, primaryFingerprint, err := parseMITMCA(primary.certificate)
	if err != nil {
		t.Fatalf("parseMITMCA(primary) error = %v", err)
	}
	_, companionAFingerprint, err := parseMITMCA(companionA.certificate)
	if err != nil {
		t.Fatalf("parseMITMCA(companionA) error = %v", err)
	}
	_, companionBFingerprint, err := parseMITMCA(companionB.certificate)
	if err != nil {
		t.Fatalf("parseMITMCA(companionB) error = %v", err)
	}
	if primaryFingerprint == companionAFingerprint || primaryFingerprint == companionBFingerprint || companionAFingerprint == companionBFingerprint {
		t.Fatalf("expected distinct fingerprints, got issuer=%q companionA=%q companionB=%q", primaryFingerprint, companionAFingerprint, companionBFingerprint)
	}

	status := engine.CAStatus()
	if got, want := status.IssuerFingerprint, primaryFingerprint; got != want {
		t.Fatalf("IssuerFingerprint = %q, want %q", got, want)
	}
	if got, want := status.CompanionFingerprints, []string{companionAFingerprint, companionBFingerprint}; !reflect.DeepEqual(got, want) {
		t.Fatalf("CompanionFingerprints = %#v, want %#v", got, want)
	}
	if got, want := status.AllFingerprints, []string{primaryFingerprint, companionAFingerprint, companionBFingerprint}; !reflect.DeepEqual(got, want) {
		t.Fatalf("AllFingerprints = %#v, want %#v", got, want)
	}
}

func TestMITMEngineEvictsLeastRecentlyUsedCertificatesWhenCacheIsFull(t *testing.T) {
	ca := newMITMTestCA(t)
	engine, err := NewMITMEngine(ca.certificate, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewMITMEngine() error = %v", err)
	}

	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	engine.AttachMetrics(m)
	engine.SetCacheMaxEntries(2)

	first, result, err := engine.CertificateForSNI("one.internal")
	if err != nil {
		t.Fatalf("CertificateForSNI(one) error = %v", err)
	}
	if result != "issued" {
		t.Fatalf("result(one) = %q, want issued", result)
	}
	if _, result, err := engine.CertificateForSNI("two.internal"); err != nil {
		t.Fatalf("CertificateForSNI(two) error = %v", err)
	} else if result != "issued" {
		t.Fatalf("result(two) = %q, want issued", result)
	}
	if _, result, err := engine.CertificateForSNI("one.internal"); err != nil {
		t.Fatalf("CertificateForSNI(one cache hit) error = %v", err)
	} else if result != "cache_hit" {
		t.Fatalf("result(one cache hit) = %q, want cache_hit", result)
	}
	if _, result, err := engine.CertificateForSNI("three.internal"); err != nil {
		t.Fatalf("CertificateForSNI(three) error = %v", err)
	} else if result != "issued" {
		t.Fatalf("result(three) = %q, want issued", result)
	}

	if got := engine.CacheEntries(); got != 2 {
		t.Fatalf("CacheEntries() = %d, want 2", got)
	}
	again, result, err := engine.CertificateForSNI("one.internal")
	if err != nil {
		t.Fatalf("CertificateForSNI(one final) error = %v", err)
	}
	if result != "cache_hit" {
		t.Fatalf("result(one final) = %q, want cache_hit", result)
	}
	if first != again {
		t.Fatal("expected most-recently-used certificate to stay cached")
	}
	if _, result, err := engine.CertificateForSNI("two.internal"); err != nil {
		t.Fatalf("CertificateForSNI(two final) error = %v", err)
	} else if result != "issued" {
		t.Fatalf("result(two final) = %q, want issued after eviction", result)
	}
	if got := counterValue(t, reg, "aegis_mitm_certificate_cache_evictions_total", map[string]string{"reason": "capacity"}); got != 2 {
		t.Fatalf("capacity eviction metric = %v, want 2", got)
	}
}

func TestMITMEngineRejectsInvalidAdditionalCA(t *testing.T) {
	primary := newMITMTestCA(t)
	leafOnly := primary.issueServerCertificate(t, "not-a-ca.internal")

	engine, err := NewMITMEngine(primary.certificate, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewMITMEngine() error = %v", err)
	}
	if err := engine.AddAdditionalCA(leafOnly); err == nil {
		t.Fatal("expected AddAdditionalCA() to reject a non-CA certificate")
	}
}

func TestProxyConnectMITMDeniesHTTPRequest(t *testing.T) {
	ca := newMITMTestCA(t)
	mitmEngine, err := NewMITMEngine(ca.certificate, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewMITMEngine() error = %v", err)
	}

	var upstreamHits atomic.Int32
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	upstream.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{ca.issueServerCertificate(t, "tunnel.internal")},
	}
	upstream.StartTLS()
	defer upstream.Close()

	proxyServer := httptest.NewServer(NewServer(Dependencies{
		Resolver: staticResolver{
			lookup: map[string][]net.IP{"tunnel.internal": {net.ParseIP("127.0.0.1")}},
		},
		IdentityResolver: staticIdentityResolver{
			identity: &identity.Identity{Labels: map[string]string{"app": "web"}},
		},
		PolicyEngine: mustPolicyEngine(t, []config.PolicyConfig{{
			Name: "allow-tls-http",
			IdentitySelector: config.IdentitySelectorConfig{
				MatchLabels: map[string]string{"app": "web"},
			},
			Egress: []config.EgressRuleConfig{{
				FQDN:  "tunnel.internal",
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
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}).Handler())
	defer proxyServer.Close()

	clientTLSConn := mustMITMConnectClient(t, proxyServer.URL, fmt.Sprintf("tunnel.internal:%d", mustPort(t, upstream.Listener.Addr().String())), ca.roots)
	defer clientTLSConn.Close()

	if _, err := fmt.Fprintf(clientTLSConn, "GET /blocked HTTP/1.1\r\nHost: tunnel.internal\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatalf("Fprintf() error = %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(clientTLSConn), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("ReadResponse() error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
	if upstreamHits.Load() != 0 {
		t.Fatalf("upstreamHits = %d, want 0", upstreamHits.Load())
	}
}

func TestProxyConnectMITMRequiresCAConfiguration(t *testing.T) {
	dnsCalls := 0
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	proxyServer := httptest.NewServer(NewServer(Dependencies{
		Resolver: countingResolver{
			lookup: map[string][]net.IP{"tunnel.internal": {net.ParseIP("127.0.0.1")}},
			calls:  &dnsCalls,
		},
		IdentityResolver: staticIdentityResolver{
			identity: &identity.Identity{Labels: map[string]string{"app": "web"}},
		},
		PolicyEngine: mustPolicyEngine(t, []config.PolicyConfig{{
			Name: "allow-tls-http",
			IdentitySelector: config.IdentitySelectorConfig{
				MatchLabels: map[string]string{"app": "web"},
			},
			Egress: []config.EgressRuleConfig{{
				FQDN:  "tunnel.internal",
				Ports: []int{443},
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

	conn, reader := mustConnectProxy(t, proxyServer.URL, "tunnel.internal:443")
	defer conn.Close()

	statusLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("ReadString() error = %v", err)
	}
	if !strings.Contains(statusLine, "500") {
		t.Fatalf("unexpected status line %q", statusLine)
	}
	if dnsCalls != 0 {
		t.Fatalf("dnsCalls = %d, want 0", dnsCalls)
	}
	if got := counterValue(t, reg, "aegis_connect_tunnels_total", map[string]string{"mode": "mitm", "result": "configuration_error"}); got != 1 {
		t.Fatalf("connect tunnel metric = %v, want 1", got)
	}
}

func TestProxyConnectMITMRecordsUpstreamTLSErrorMetric(t *testing.T) {
	ca := newMITMTestCA(t)
	otherCA := newMITMTestCA(t)
	mitmEngine, err := NewMITMEngine(ca.certificate, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewMITMEngine() error = %v", err)
	}

	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	upstream.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{otherCA.issueServerCertificate(t, "tunnel.internal")},
	}
	upstream.StartTLS()
	defer upstream.Close()

	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	proxyServer := httptest.NewServer(NewServer(Dependencies{
		Resolver: staticResolver{
			lookup: map[string][]net.IP{"tunnel.internal": {net.ParseIP("127.0.0.1")}},
		},
		DestinationGuard: mustDestinationGuard(t, nil, []string{"127.0.0.0/8"}),
		IdentityResolver: staticIdentityResolver{
			identity: &identity.Identity{Labels: map[string]string{"app": "web"}},
		},
		PolicyEngine: mustPolicyEngine(t, []config.PolicyConfig{{
			Name: "allow-tls-http",
			IdentitySelector: config.IdentitySelectorConfig{
				MatchLabels: map[string]string{"app": "web"},
			},
			Egress: []config.EgressRuleConfig{{
				FQDN:  "tunnel.internal",
				Ports: []int{mustPort(t, upstream.Listener.Addr().String())},
				TLS:   config.TLSRuleConfig{Mode: "mitm"},
				HTTP: &config.HTTPRuleConfig{
					AllowedMethods: []string{"GET"},
					AllowedPaths:   []string{"/*"},
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
	defer proxyServer.Close()

	clientTLSConn := mustMITMConnectClient(t, proxyServer.URL, fmt.Sprintf("tunnel.internal:%d", mustPort(t, upstream.Listener.Addr().String())), ca.roots)
	defer clientTLSConn.Close()

	if _, err := fmt.Fprintf(clientTLSConn, "GET /allowed HTTP/1.1\r\nHost: tunnel.internal\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatalf("Fprintf() error = %v", err)
	}

	_ = clientTLSConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	_, _ = clientTLSConn.Read(buf)

	if got := counterValue(t, reg, "aegis_upstream_tls_errors_total", map[string]string{"stage": "handshake"}); got != 1 {
		t.Fatalf("upstream tls error metric = %v, want 1", got)
	}
}

func TestMITMEngineCertificateForSNICachesCertificates(t *testing.T) {
	ca := newMITMTestCA(t)
	engine, err := NewMITMEngine(ca.certificate, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewMITMEngine() error = %v", err)
	}

	first, firstResult, err := engine.CertificateForSNI("tunnel.internal")
	if err != nil {
		t.Fatalf("CertificateForSNI() first error = %v", err)
	}
	second, secondResult, err := engine.CertificateForSNI("tunnel.internal")
	if err != nil {
		t.Fatalf("CertificateForSNI() second error = %v", err)
	}

	if firstResult != "issued" {
		t.Fatalf("first result = %q, want issued", firstResult)
	}
	if secondResult != "cache_hit" {
		t.Fatalf("second result = %q, want cache_hit", secondResult)
	}
	if first != second {
		t.Fatalf("certificate pointers differ: %p vs %p", first, second)
	}
}

type mitmTestCA struct {
	certificate tls.Certificate
	roots       *x509.CertPool
	leaf        *x509.Certificate
}

func newMITMTestCA(t *testing.T) mitmTestCA {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Aegis Test Root",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}

	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}

	certificate := tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        leaf,
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)

	return mitmTestCA{
		certificate: certificate,
		roots:       roots,
		leaf:        leaf,
	}
}

func (ca mitmTestCA) issueServerCertificate(t *testing.T, serverName string) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("rand.Int() error = %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: serverName,
		},
		DNSNames:              []string{serverName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, ca.leaf, key.Public(), ca.certificate.PrivateKey)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}

	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        leaf,
	}
}

func mustMITMConnectClient(t *testing.T, proxyAddr string, target string, roots *x509.CertPool) *tls.Conn {
	t.Helper()

	conn, reader := mustConnectProxy(t, proxyAddr, target)
	readConnectEstablished(t, reader)

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName: "tunnel.internal",
		RootCAs:    roots,
		MinVersion: tls.VersionTLS12,
	})
	if err := tlsConn.Handshake(); err != nil {
		conn.Close()
		t.Fatalf("Handshake() error = %v", err)
	}

	return tlsConn
}
