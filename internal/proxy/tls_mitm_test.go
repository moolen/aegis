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
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/moolen/aegis/internal/config"
	"github.com/moolen/aegis/internal/identity"
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
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
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
