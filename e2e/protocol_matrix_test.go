//go:build e2e

package e2e

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestCONNECTPassthroughAllowed(t *testing.T) {
	const host = "passthrough.internal"

	tempDir := t.TempDir()
	upstreamCA := newTestCA(t, tempDir, "upstream-passthrough")
	serverCert := issueServerCertificate(t, upstreamCA, host)
	upstream := startTLSServer(t, serverCert, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/allowed" {
			t.Fatalf("path = %q, want %q", r.URL.Path, "/allowed")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	dnsServer := startStaticDNSServer(t, map[string]net.IP{host: net.ParseIP("127.0.0.1")})

	proxyAddr := reserveTCPAddr(t)
	metricsAddr := reserveTCPAddr(t)
	configPath := filepath.Join(tempDir, "aegis.yaml")
	writeConfig(t, configPath, proxyConfigYAML(proxyConfigSpec{
		ProxyAddr:           proxyAddr,
		MetricsAddr:         metricsAddr,
		DNSServers:          []string{dnsServer},
		AllowedHostPatterns: []string{"*.internal"},
		PolicyName:          "allow-passthrough",
		PolicyFQDN:          host,
		PolicyPort:          mustPort(t, upstream.Listener.Addr().String()),
		TLSMode:             "passthrough",
	}))

	startAegis(t, configPath)

	client := httpsProxyClient(proxyAddr, &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    upstreamCA.RootPool,
	})
	resp, err := client.Get(fmt.Sprintf("https://%s:%d/allowed", host, mustPort(t, upstream.Listener.Addr().String())))
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}

	metricsBody := fetchMetrics(t, "http://"+metricsAddr)
	if got := metricValue(t, metricsBody, "aegis_connect_tunnels_total", map[string]string{"mode": "passthrough", "result": "established"}); got != 1 {
		t.Fatalf("passthrough established metric = %v, want 1", got)
	}
}

func TestCONNECTPassthroughDenied(t *testing.T) {
	const (
		allowedHost = "allowed.internal"
		targetHost  = "denied.internal"
	)

	proxyAddr := reserveTCPAddr(t)
	metricsAddr := reserveTCPAddr(t)
	configPath := filepath.Join(t.TempDir(), "aegis.yaml")
	writeConfig(t, configPath, proxyConfigYAML(proxyConfigSpec{
		ProxyAddr:   proxyAddr,
		MetricsAddr: metricsAddr,
		PolicyName:  "allow-other",
		PolicyFQDN:  allowedHost,
		PolicyPort:  443,
		TLSMode:     "passthrough",
	}))

	startAegis(t, configPath)

	conn, reader, resp := openConnectTunnel(t, proxyAddr, fmt.Sprintf("%s:%d", targetHost, 443))
	defer conn.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("CONNECT status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	_ = reader
	if !strings.Contains(string(body), "connect target denied by policy") {
		t.Fatalf("body = %q, want policy denial", string(body))
	}
}

func TestCONNECTAuditModeAllowsDeniedTargets(t *testing.T) {
	const (
		allowedHost = "allowed.internal"
		targetHost  = "audit-denied.internal"
	)

	tempDir := t.TempDir()
	upstreamCA := newTestCA(t, tempDir, "upstream-audit-connect")
	serverCert := issueServerCertificate(t, upstreamCA, targetHost)
	upstream := startTLSServer(t, serverCert, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	dnsServer := startStaticDNSServer(t, map[string]net.IP{targetHost: net.ParseIP("127.0.0.1")})

	proxyAddr := reserveTCPAddr(t)
	metricsAddr := reserveTCPAddr(t)
	configPath := filepath.Join(tempDir, "aegis.yaml")
	writeConfig(t, configPath, proxyConfigYAML(proxyConfigSpec{
		ProxyAddr:           proxyAddr,
		MetricsAddr:         metricsAddr,
		DNSServers:          []string{dnsServer},
		AllowedHostPatterns: []string{"*.internal"},
		Enforcement:         "audit",
		PolicyName:          "allow-other",
		PolicyFQDN:          allowedHost,
		PolicyPort:          mustPort(t, upstream.Listener.Addr().String()),
		TLSMode:             "passthrough",
	}))

	startAegis(t, configPath)

	client := httpsProxyClient(proxyAddr, &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    upstreamCA.RootPool,
	})
	resp, err := client.Get(fmt.Sprintf("https://%s:%d/allowed", targetHost, mustPort(t, upstream.Listener.Addr().String())))
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}

	metricsBody := fetchMetrics(t, "http://"+metricsAddr)
	if got := metricValue(t, metricsBody, "aegis_request_decisions_total", map[string]string{
		"protocol": "connect",
		"action":   "allow",
		"policy":   "allow-other",
		"reason":   "audit_policy_denied",
	}); got != 1 {
		t.Fatalf("actual decision metric = %v, want 1", got)
	}
	if got := metricValue(t, metricsBody, "aegis_audit_decisions_total", map[string]string{
		"protocol": "connect",
		"action":   "would_deny",
		"identity": "i-localhost",
		"fqdn":     targetHost,
		"policy":   "allow-other",
		"reason":   "policy_denied",
	}); got != 1 {
		t.Fatalf("audit decision metric = %v, want 1", got)
	}
}

func TestCONNECTPolicyLevelAuditAllowsDeniedTargets(t *testing.T) {
	const (
		allowedHost = "allowed.internal"
		targetHost  = "policy-audit-denied.internal"
	)

	tempDir := t.TempDir()
	upstreamCA := newTestCA(t, tempDir, "upstream-policy-audit-connect")
	serverCert := issueServerCertificate(t, upstreamCA, targetHost)
	upstream := startTLSServer(t, serverCert, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	dnsServer := startStaticDNSServer(t, map[string]net.IP{targetHost: net.ParseIP("127.0.0.1")})

	proxyAddr := reserveTCPAddr(t)
	metricsAddr := reserveTCPAddr(t)
	configPath := filepath.Join(tempDir, "aegis.yaml")
	writeConfig(t, configPath, proxyConfigYAML(proxyConfigSpec{
		ProxyAddr:           proxyAddr,
		MetricsAddr:         metricsAddr,
		DNSServers:          []string{dnsServer},
		AllowedHostPatterns: []string{"*.internal"},
		PolicyEnforcement:   "audit",
		PolicyName:          "allow-other",
		PolicyFQDN:          allowedHost,
		PolicyPort:          mustPort(t, upstream.Listener.Addr().String()),
		TLSMode:             "passthrough",
	}))

	startAegis(t, configPath)

	client := httpsProxyClient(proxyAddr, &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    upstreamCA.RootPool,
	})
	resp, err := client.Get(fmt.Sprintf("https://%s:%d/allowed", targetHost, mustPort(t, upstream.Listener.Addr().String())))
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}
}

func TestCONNECTAdminEnforcementKillSwitchAllowsDeniedTargets(t *testing.T) {
	const (
		adminToken  = "test-admin-token"
		allowedHost = "allowed.internal"
		targetHost  = "switch-denied.internal"
	)

	tempDir := t.TempDir()
	upstreamCA := newTestCA(t, tempDir, "upstream-switch-connect")
	serverCert := issueServerCertificate(t, upstreamCA, targetHost)
	upstream := startTLSServer(t, serverCert, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	dnsServer := startStaticDNSServer(t, map[string]net.IP{targetHost: net.ParseIP("127.0.0.1")})

	proxyAddr := reserveTCPAddr(t)
	metricsAddr := reserveTCPAddr(t)
	configPath := filepath.Join(tempDir, "aegis.yaml")
	writeConfig(t, configPath, proxyConfigYAML(proxyConfigSpec{
		ProxyAddr:           proxyAddr,
		MetricsAddr:         metricsAddr,
		AdminToken:          adminToken,
		DNSServers:          []string{dnsServer},
		AllowedHostPatterns: []string{"*.internal"},
		PolicyName:          "allow-other",
		PolicyFQDN:          allowedHost,
		PolicyPort:          mustPort(t, upstream.Listener.Addr().String()),
		TLSMode:             "passthrough",
	}))

	startAegis(t, configPath)

	conn, reader, resp := openConnectTunnel(t, proxyAddr, fmt.Sprintf("%s:%d", targetHost, mustPort(t, upstream.Listener.Addr().String())))
	resp.Body.Close()
	reader.Reset(conn)
	conn.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("initial CONNECT status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}

	adminResp, err := setAdminEnforcementMode("http://"+metricsAddr, adminToken, "audit")
	if err != nil {
		t.Fatalf("setAdminEnforcementMode(audit) error = %v", err)
	}
	adminResp.Body.Close()
	if adminResp.StatusCode != http.StatusOK {
		t.Fatalf("admin audit status = %d, want %d", adminResp.StatusCode, http.StatusOK)
	}

	client := httpsProxyClient(proxyAddr, &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    upstreamCA.RootPool,
	})
	resp, err = client.Get(fmt.Sprintf("https://%s:%d/allowed", targetHost, mustPort(t, upstream.Listener.Addr().String())))
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("audit status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}

	adminResp, err = setAdminEnforcementMode("http://"+metricsAddr, adminToken, "config")
	if err != nil {
		t.Fatalf("setAdminEnforcementMode(config) error = %v", err)
	}
	adminResp.Body.Close()
	if adminResp.StatusCode != http.StatusOK {
		t.Fatalf("admin config status = %d, want %d", adminResp.StatusCode, http.StatusOK)
	}

	conn, reader, resp = openConnectTunnel(t, proxyAddr, fmt.Sprintf("%s:%d", targetHost, mustPort(t, upstream.Listener.Addr().String())))
	resp.Body.Close()
	reader.Reset(conn)
	conn.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("restored CONNECT status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
}

func TestCONNECTBypassAllowsDeniedTargets(t *testing.T) {
	const (
		allowedHost = "allowed.internal"
		targetHost  = "bypass-denied.internal"
	)

	tempDir := t.TempDir()
	upstreamCA := newTestCA(t, tempDir, "upstream-bypass-connect")
	serverCert := issueServerCertificate(t, upstreamCA, targetHost)
	upstream := startTLSServer(t, serverCert, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	dnsServer := startStaticDNSServer(t, map[string]net.IP{targetHost: net.ParseIP("127.0.0.1")})

	proxyAddr := reserveTCPAddr(t)
	metricsAddr := reserveTCPAddr(t)
	configPath := filepath.Join(tempDir, "aegis.yaml")
	writeConfig(t, configPath, proxyConfigYAML(proxyConfigSpec{
		ProxyAddr:           proxyAddr,
		MetricsAddr:         metricsAddr,
		DNSServers:          []string{dnsServer},
		AllowedHostPatterns: []string{"*.internal"},
		PolicyBypass:        true,
		PolicyName:          "break-glass",
		PolicyFQDN:          allowedHost,
		PolicyPort:          mustPort(t, upstream.Listener.Addr().String()),
		TLSMode:             "passthrough",
	}))

	startAegis(t, configPath)

	client := httpsProxyClient(proxyAddr, &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    upstreamCA.RootPool,
	})
	resp, err := client.Get(fmt.Sprintf("https://%s:%d/allowed", targetHost, mustPort(t, upstream.Listener.Addr().String())))
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}

	metricsBody := fetchMetrics(t, "http://"+metricsAddr)
	if got := metricValue(t, metricsBody, "aegis_request_decisions_total", map[string]string{
		"protocol": "connect",
		"action":   "allow",
		"policy":   "break-glass",
		"reason":   "audit_policy_denied",
	}); got != 1 {
		t.Fatalf("actual decision metric = %v, want 1", got)
	}
	if got := metricValue(t, metricsBody, "aegis_audit_decisions_total", map[string]string{
		"protocol": "connect",
		"action":   "would_deny",
		"identity": "i-localhost",
		"fqdn":     targetHost,
		"policy":   "break-glass",
		"reason":   "policy_denied",
	}); got != 1 {
		t.Fatalf("audit decision metric = %v, want 1", got)
	}
}

func TestCONNECTConnectionLimitRejectsSecondConcurrentTunnel(t *testing.T) {
	const targetHost = "limit.internal"

	upstream := startDiscardTCPServer(t)
	dnsServer := startStaticDNSServer(t, map[string]net.IP{targetHost: net.ParseIP("127.0.0.1")})

	proxyAddr := reserveTCPAddr(t)
	metricsAddr := reserveTCPAddr(t)
	configPath := filepath.Join(t.TempDir(), "aegis.yaml")
	writeConfig(t, configPath, proxyConfigYAML(proxyConfigSpec{
		ProxyAddr:                proxyAddr,
		MetricsAddr:              metricsAddr,
		DNSServers:               []string{dnsServer},
		AllowedHostPatterns:      []string{"*.internal"},
		MaxConcurrentPerIdentity: 1,
		PolicyName:               "allow-connect",
		PolicyFQDN:               targetHost,
		PolicyPort:               mustPort(t, upstream.Addr().String()),
		TLSMode:                  "passthrough",
	}))

	startAegis(t, configPath)

	target := fmt.Sprintf("%s:%d", targetHost, mustPort(t, upstream.Addr().String()))
	conn, _, resp := openConnectTunnel(t, proxyAddr, target)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first CONNECT status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	resp.Body.Close()
	defer conn.Close()

	secondConn, _, secondResp := openConnectTunnel(t, proxyAddr, target)
	secondConn.Close()
	defer secondResp.Body.Close()
	if secondResp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second CONNECT status = %d, want %d", secondResp.StatusCode, http.StatusTooManyRequests)
	}

	metricsBody := fetchMetrics(t, "http://"+metricsAddr)
	if got := metricValue(t, metricsBody, "aegis_identity_connection_limit_rejections_total", map[string]string{"protocol": "connect"}); got != 1 {
		t.Fatalf("connect limit rejection metric = %v, want 1", got)
	}
	if got := metricValue(t, metricsBody, "aegis_request_decisions_total", map[string]string{
		"protocol": "connect",
		"action":   "deny",
		"policy":   "allow-connect",
		"reason":   "connection_limit_exceeded",
	}); got != 1 {
		t.Fatalf("connect deny decision metric = %v, want 1", got)
	}
}

func TestTLSNoSNIBlocked(t *testing.T) {
	const host = "nosni.internal"

	upstream := startDiscardTCPServer(t)
	dnsServer := startStaticDNSServer(t, map[string]net.IP{host: net.ParseIP("127.0.0.1")})

	proxyAddr := reserveTCPAddr(t)
	metricsAddr := reserveTCPAddr(t)
	configPath := filepath.Join(t.TempDir(), "aegis.yaml")
	writeConfig(t, configPath, proxyConfigYAML(proxyConfigSpec{
		ProxyAddr:           proxyAddr,
		MetricsAddr:         metricsAddr,
		DNSServers:          []string{dnsServer},
		AllowedHostPatterns: []string{"*.internal"},
		PolicyName:          "allow-nosni",
		PolicyFQDN:          host,
		PolicyPort:          mustPort(t, upstream.Addr().String()),
		TLSMode:             "passthrough",
	}))

	startAegis(t, configPath)

	conn, reader, resp := openConnectTunnel(t, proxyAddr, fmt.Sprintf("%s:%d", host, mustPort(t, upstream.Addr().String())))
	defer conn.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	if _, err := conn.Write(mustTLSClientHello(t, "")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	expectConnectionClose(t, conn, reader)

	waitFor(t, 5*time.Second, func() bool {
		metricsBody := fetchMetrics(t, "http://"+metricsAddr)
		value, ok := metricValueOrZero(metricsBody, "aegis_tls_sni_missing_total", map[string]string{})
		return ok && value == 1
	})

	metricsBody := fetchMetrics(t, "http://"+metricsAddr)
	if got := metricValue(t, metricsBody, "aegis_connect_tunnels_total", map[string]string{"mode": "passthrough", "result": "tls_blocked"}); got != 1 {
		t.Fatalf("tls blocked metric = %v, want 1", got)
	}
}

func TestTLSSNIMismatchBlocked(t *testing.T) {
	const (
		targetHost = "match.internal"
		clientSNI  = "other.internal"
	)

	upstream := startDiscardTCPServer(t)
	dnsServer := startStaticDNSServer(t, map[string]net.IP{targetHost: net.ParseIP("127.0.0.1")})

	proxyAddr := reserveTCPAddr(t)
	metricsAddr := reserveTCPAddr(t)
	configPath := filepath.Join(t.TempDir(), "aegis.yaml")
	writeConfig(t, configPath, proxyConfigYAML(proxyConfigSpec{
		ProxyAddr:           proxyAddr,
		MetricsAddr:         metricsAddr,
		DNSServers:          []string{dnsServer},
		AllowedHostPatterns: []string{"*.internal"},
		PolicyName:          "allow-target",
		PolicyFQDN:          targetHost,
		PolicyPort:          mustPort(t, upstream.Addr().String()),
		TLSMode:             "passthrough",
	}))

	startAegis(t, configPath)

	conn, reader, resp := openConnectTunnel(t, proxyAddr, fmt.Sprintf("%s:%d", targetHost, mustPort(t, upstream.Addr().String())))
	defer conn.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	if _, err := conn.Write(mustTLSClientHello(t, clientSNI)); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	expectConnectionClose(t, conn, reader)

	metricsBody := fetchMetrics(t, "http://"+metricsAddr)
	if got := metricValue(t, metricsBody, "aegis_connect_tunnels_total", map[string]string{"mode": "passthrough", "result": "tls_blocked"}); got != 1 {
		t.Fatalf("tls blocked metric = %v, want 1", got)
	}
}

func TestMITMCertGeneratedForTargetSNI(t *testing.T) {
	const host = "mitm-cert.internal"

	tempDir := t.TempDir()
	proxyCA := newTestCA(t, tempDir, "proxy-mitm")
	upstreamCA := newTestCA(t, tempDir, "upstream-mitm")
	serverCert := issueServerCertificate(t, upstreamCA, host)
	upstream := startTLSServer(t, serverCert, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	dnsServer := startStaticDNSServer(t, map[string]net.IP{host: net.ParseIP("127.0.0.1")})

	proxyAddr := reserveTCPAddr(t)
	metricsAddr := reserveTCPAddr(t)
	configPath := filepath.Join(tempDir, "aegis.yaml")
	writeConfig(t, configPath, proxyConfigYAML(proxyConfigSpec{
		ProxyAddr:           proxyAddr,
		MetricsAddr:         metricsAddr,
		DNSServers:          []string{dnsServer},
		AllowedHostPatterns: []string{"*.internal"},
		ProxyCACertFile:     proxyCA.CertFile,
		ProxyCAKeyFile:      proxyCA.KeyFile,
		PolicyName:          "allow-mitm",
		PolicyFQDN:          host,
		PolicyPort:          mustPort(t, upstream.Listener.Addr().String()),
		TLSMode:             "mitm",
		AllowedMethods:      []string{"GET"},
		AllowedPaths:        []string{"/*"},
	}))

	var peer *x509.Certificate
	startAegisWithEnv(t, configPath, []string{"SSL_CERT_FILE=" + upstreamCA.CertFile})

	client := httpsProxyClient(proxyAddr, &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    proxyCA.RootPool,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return fmt.Errorf("missing peer certificate")
			}
			peer = state.PeerCertificates[0]
			return nil
		},
	})
	resp, err := client.Get(fmt.Sprintf("https://%s:%d/allowed", host, mustPort(t, upstream.Listener.Addr().String())))
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}
	if peer == nil {
		t.Fatal("expected to capture peer certificate")
	}
	if peer.Subject.CommonName != host {
		t.Fatalf("peer common name = %q, want %q", peer.Subject.CommonName, host)
	}
	if len(peer.DNSNames) != 1 || peer.DNSNames[0] != host {
		t.Fatalf("peer dns names = %#v, want [%q]", peer.DNSNames, host)
	}
	if peer.Issuer.CommonName != proxyCA.Leaf.Subject.CommonName {
		t.Fatalf("peer issuer = %q, want %q", peer.Issuer.CommonName, proxyCA.Leaf.Subject.CommonName)
	}

	metricsBody := fetchMetrics(t, "http://"+metricsAddr)
	if got := metricValue(t, metricsBody, "aegis_mitm_certificates_total", map[string]string{"result": "issued"}); got != 1 {
		t.Fatalf("mitm issued metric = %v, want 1", got)
	}
}

func TestMITMHTTPInspectionDeniesBlockedPath(t *testing.T) {
	const host = "mitm-deny.internal"

	tempDir := t.TempDir()
	proxyCA := newTestCA(t, tempDir, "proxy-mitm-deny")
	upstreamCA := newTestCA(t, tempDir, "upstream-mitm-deny")
	serverCert := issueServerCertificate(t, upstreamCA, host)
	upstream := startTLSServer(t, serverCert, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	dnsServer := startStaticDNSServer(t, map[string]net.IP{host: net.ParseIP("127.0.0.1")})

	proxyAddr := reserveTCPAddr(t)
	metricsAddr := reserveTCPAddr(t)
	configPath := filepath.Join(tempDir, "aegis.yaml")
	writeConfig(t, configPath, proxyConfigYAML(proxyConfigSpec{
		ProxyAddr:           proxyAddr,
		MetricsAddr:         metricsAddr,
		DNSServers:          []string{dnsServer},
		AllowedHostPatterns: []string{"*.internal"},
		ProxyCACertFile:     proxyCA.CertFile,
		ProxyCAKeyFile:      proxyCA.KeyFile,
		PolicyName:          "allow-mitm-path",
		PolicyFQDN:          host,
		PolicyPort:          mustPort(t, upstream.Listener.Addr().String()),
		TLSMode:             "mitm",
		AllowedMethods:      []string{"GET"},
		AllowedPaths:        []string{"/allowed"},
	}))

	startAegisWithEnv(t, configPath, []string{"SSL_CERT_FILE=" + upstreamCA.CertFile})

	client := httpsProxyClient(proxyAddr, &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    proxyCA.RootPool,
	})
	resp, err := client.Get(fmt.Sprintf("https://%s:%d/denied", host, mustPort(t, upstream.Listener.Addr().String())))
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}

	metricsBody := fetchMetrics(t, "http://"+metricsAddr)
	if got := metricValue(t, metricsBody, "aegis_request_decisions_total", map[string]string{
		"protocol": "mitm_http",
		"action":   "deny",
		"policy":   "allow-mitm-path",
		"reason":   "policy_denied",
	}); got != 1 {
		t.Fatalf("mitm deny metric = %v, want 1", got)
	}
}

func TestMITMClientWithoutCAFails(t *testing.T) {
	const host = "mitm-client-fail.internal"

	tempDir := t.TempDir()
	proxyCA := newTestCA(t, tempDir, "proxy-mitm-client-fail")
	upstreamCA := newTestCA(t, tempDir, "upstream-mitm-client-fail")
	serverCert := issueServerCertificate(t, upstreamCA, host)
	upstream := startTLSServer(t, serverCert, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	dnsServer := startStaticDNSServer(t, map[string]net.IP{host: net.ParseIP("127.0.0.1")})

	proxyAddr := reserveTCPAddr(t)
	metricsAddr := reserveTCPAddr(t)
	configPath := filepath.Join(tempDir, "aegis.yaml")
	writeConfig(t, configPath, proxyConfigYAML(proxyConfigSpec{
		ProxyAddr:           proxyAddr,
		MetricsAddr:         metricsAddr,
		DNSServers:          []string{dnsServer},
		AllowedHostPatterns: []string{"*.internal"},
		ProxyCACertFile:     proxyCA.CertFile,
		ProxyCAKeyFile:      proxyCA.KeyFile,
		PolicyName:          "allow-mitm-client-fail",
		PolicyFQDN:          host,
		PolicyPort:          mustPort(t, upstream.Listener.Addr().String()),
		TLSMode:             "mitm",
		AllowedMethods:      []string{"GET"},
		AllowedPaths:        []string{"/*"},
	}))

	startAegisWithEnv(t, configPath, []string{"SSL_CERT_FILE=" + upstreamCA.CertFile})

	client := httpsProxyClient(proxyAddr, &tls.Config{
		MinVersion: tls.VersionTLS12,
	})
	_, err := client.Get(fmt.Sprintf("https://%s:%d/allowed", host, mustPort(t, upstream.Listener.Addr().String())))
	if err == nil {
		t.Fatal("expected TLS client request to fail without proxy CA trust")
	}
	if !strings.Contains(err.Error(), "unknown authority") {
		t.Fatalf("error = %v, want unknown authority", err)
	}
}

func TestMITMUpstreamCertValidated(t *testing.T) {
	const host = "mitm-upstream.internal"

	tempDir := t.TempDir()
	proxyCA := newTestCA(t, tempDir, "proxy-mitm-upstream")
	upstreamCA := newTestCA(t, tempDir, "upstream-mitm-upstream")
	serverCert := issueServerCertificate(t, upstreamCA, host)
	upstream := startTLSServer(t, serverCert, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	dnsServer := startStaticDNSServer(t, map[string]net.IP{host: net.ParseIP("127.0.0.1")})

	proxyAddr := reserveTCPAddr(t)
	metricsAddr := reserveTCPAddr(t)
	configPath := filepath.Join(tempDir, "aegis.yaml")
	writeConfig(t, configPath, proxyConfigYAML(proxyConfigSpec{
		ProxyAddr:           proxyAddr,
		MetricsAddr:         metricsAddr,
		DNSServers:          []string{dnsServer},
		AllowedHostPatterns: []string{"*.internal"},
		ProxyCACertFile:     proxyCA.CertFile,
		ProxyCAKeyFile:      proxyCA.KeyFile,
		PolicyName:          "allow-mitm-upstream",
		PolicyFQDN:          host,
		PolicyPort:          mustPort(t, upstream.Listener.Addr().String()),
		TLSMode:             "mitm",
		AllowedMethods:      []string{"GET"},
		AllowedPaths:        []string{"/*"},
	}))

	startAegis(t, configPath)

	client := httpsProxyClient(proxyAddr, &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    proxyCA.RootPool,
	})
	_, err := client.Get(fmt.Sprintf("https://%s:%d/allowed", host, mustPort(t, upstream.Listener.Addr().String())))
	if err == nil {
		t.Fatal("expected upstream TLS validation failure")
	}

	waitFor(t, 5*time.Second, func() bool {
		metricsBody := fetchMetrics(t, "http://"+metricsAddr)
		value, ok := metricValueOrZero(metricsBody, "aegis_upstream_tls_errors_total", map[string]string{"stage": "handshake"})
		return ok && value == 1
	})

	metricsBody := fetchMetrics(t, "http://"+metricsAddr)
	if got := metricValue(t, metricsBody, "aegis_connect_tunnels_total", map[string]string{"mode": "mitm", "result": "upstream_tls_error"}); got != 1 {
		t.Fatalf("upstream tls error metric = %v, want 1", got)
	}
}

type proxyConfigSpec struct {
	ProxyAddr                string
	MetricsAddr              string
	AdminToken               string
	DNSServers               []string
	AllowedHostPatterns      []string
	AllowedCIDRs             []string
	Enforcement              string
	UnknownIdentityPolicy    string
	PolicyBypass             bool
	PolicyEnforcement        string
	MaxConcurrentPerIdentity int
	ProxyCACertFile          string
	ProxyCAKeyFile           string
	PolicyName               string
	PolicyFQDN               string
	PolicyPort               int
	TLSMode                  string
	AllowedMethods           []string
	AllowedPaths             []string
}

func proxyConfigYAML(spec proxyConfigSpec) string {
	var b strings.Builder
	fmt.Fprintf(&b, "proxy:\n  listen: %q\n", spec.ProxyAddr)
	if spec.Enforcement != "" {
		fmt.Fprintf(&b, "  enforcement: %s\n", spec.Enforcement)
	}
	if spec.UnknownIdentityPolicy != "" {
		fmt.Fprintf(&b, "  unknownIdentityPolicy: %s\n", spec.UnknownIdentityPolicy)
	}
	if spec.MaxConcurrentPerIdentity > 0 {
		fmt.Fprintf(&b, "  connectionLimits:\n    maxConcurrentPerIdentity: %d\n", spec.MaxConcurrentPerIdentity)
	}
	if spec.ProxyCACertFile != "" || spec.ProxyCAKeyFile != "" {
		fmt.Fprintf(&b, "  ca:\n    certFile: %q\n    keyFile: %q\n", spec.ProxyCACertFile, spec.ProxyCAKeyFile)
	}
	if spec.AdminToken != "" {
		fmt.Fprintf(&b, "admin:\n  token: %q\n", spec.AdminToken)
	}
	fmt.Fprintf(&b, "metrics:\n  listen: %q\n", spec.MetricsAddr)
	fmt.Fprint(&b, "shutdown:\n  gracePeriod: 10s\n")
	fmt.Fprint(&b, "dns:\n  cache_ttl: 30s\n  timeout: 5s\n")
	fmt.Fprintf(&b, "  servers: %s\n", yamlStringList(spec.DNSServers))
	fmt.Fprint(&b, "  rebindingProtection:\n")
	fmt.Fprintf(&b, "    allowedHostPatterns: %s\n", yamlStringList(spec.AllowedHostPatterns))
	fmt.Fprintf(&b, "    allowedCIDRs: %s\n", yamlStringList(spec.AllowedCIDRs))
	fmt.Fprintf(&b, "discovery:\n  ec2:\n    - name: %s\n      region: us-east-1\n      tagFilters:\n        - key: %q\n          values: [%q]\n", defaultE2EEC2ProviderName, defaultE2EEC2TagKey, defaultE2EEC2TagValue)
	fmt.Fprintf(&b, "policies:\n  - name: %s\n", spec.PolicyName)
	if spec.PolicyEnforcement != "" {
		fmt.Fprintf(&b, "    enforcement: %s\n", spec.PolicyEnforcement)
	}
	if spec.PolicyBypass {
		fmt.Fprint(&b, "    bypass: true\n")
	}
	fmt.Fprintf(&b, "    subjects:\n      ec2:\n        discoveryNames: [%q]\n    egress:\n      - fqdn: %q\n        ports: [%d]\n        tls:\n          mode: %s\n",
		defaultE2EEC2ProviderName, spec.PolicyFQDN, spec.PolicyPort, spec.TLSMode)
	if len(spec.AllowedMethods) > 0 || len(spec.AllowedPaths) > 0 {
		fmt.Fprint(&b, "        http:\n")
		fmt.Fprintf(&b, "          allowedMethods: %s\n", yamlStringList(spec.AllowedMethods))
		fmt.Fprintf(&b, "          allowedPaths: %s\n", yamlStringList(spec.AllowedPaths))
	}
	return b.String()
}

func yamlStringList(values []string) string {
	if len(values) == 0 {
		return "[]"
	}
	quoted := make([]string, 0, len(values))
	for _, value := range values {
		quoted = append(quoted, fmt.Sprintf("%q", value))
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}

type testCA struct {
	CertFile string
	KeyFile  string
	CertPEM  []byte
	TLSCert  tls.Certificate
	Leaf     *x509.Certificate
	RootPool *x509.CertPool
}

func newTestCA(t *testing.T, dir string, commonName string) *testCA {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: commonName,
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
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey() error = %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	certFile := filepath.Join(dir, commonName+".crt")
	keyFile := filepath.Join(dir, commonName+".key")
	if err := os.WriteFile(certFile, certPEM, 0o644); err != nil {
		t.Fatalf("WriteFile(cert) error = %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatalf("WriteFile(key) error = %v", err)
	}

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair() error = %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}
	tlsCert.Leaf = leaf

	rootPool := x509.NewCertPool()
	rootPool.AppendCertsFromPEM(certPEM)

	return &testCA{
		CertFile: certFile,
		KeyFile:  keyFile,
		CertPEM:  certPEM,
		TLSCert:  tlsCert,
		Leaf:     leaf,
		RootPool: rootPool,
	}
}

func issueServerCertificate(t *testing.T, ca *testCA, serverName string) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
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

	der, err := x509.CreateCertificate(rand.Reader, template, ca.Leaf, key.Public(), ca.TLSCert.PrivateKey)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey() error = %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	serverCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair() error = %v", err)
	}
	serverCert.Certificate = append(serverCert.Certificate, ca.TLSCert.Certificate...)
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}
	serverCert.Leaf = leaf

	return serverCert
}

func startTLSServer(t *testing.T, certificate tls.Certificate, handler http.Handler) *httptest.Server {
	t.Helper()

	server := httptest.NewUnstartedServer(handler)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	server.Listener = listener
	server.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{certificate},
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func httpsProxyClient(proxyAddr string, tlsConfig *tls.Config) *http.Client {
	transport := &http.Transport{
		DisableKeepAlives: true,
		Proxy: func(*http.Request) (*url.URL, error) {
			return url.Parse("http://" + proxyAddr)
		},
		TLSClientConfig: tlsConfig,
	}
	return &http.Client{Transport: transport}
}

type staticDNSServer struct {
	packetConn net.PacketConn
	records    map[string]net.IP
}

func startStaticDNSServer(t *testing.T, records map[string]net.IP) string {
	t.Helper()

	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}

	server := &staticDNSServer{
		packetConn: packetConn,
		records:    records,
	}
	go server.serve()

	t.Cleanup(func() {
		_ = packetConn.Close()
	})

	return packetConn.LocalAddr().String()
}

func (s *staticDNSServer) serve() {
	buf := make([]byte, 512)
	for {
		n, addr, err := s.packetConn.ReadFrom(buf)
		if err != nil {
			return
		}

		response, err := s.buildResponse(buf[:n])
		if err != nil {
			continue
		}
		if _, err := s.packetConn.WriteTo(response, addr); err != nil {
			return
		}
	}
}

func (s *staticDNSServer) buildResponse(query []byte) ([]byte, error) {
	var parser dnsmessage.Parser
	header, err := parser.Start(query)
	if err != nil {
		return nil, err
	}
	question, err := parser.Question()
	if err != nil {
		return nil, err
	}

	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:                 header.ID,
		Response:           true,
		RecursionAvailable: true,
	})
	builder.EnableCompression()
	if err := builder.StartQuestions(); err != nil {
		return nil, err
	}
	if err := builder.Question(question); err != nil {
		return nil, err
	}
	if err := builder.StartAnswers(); err != nil {
		return nil, err
	}

	host := strings.TrimSuffix(question.Name.String(), ".")
	ip := s.records[host]
	if ip != nil {
		resourceHeader := dnsmessage.ResourceHeader{
			Name:  question.Name,
			Class: question.Class,
			TTL:   30,
		}
		if ipv4 := ip.To4(); question.Type == dnsmessage.TypeA && ipv4 != nil {
			var addr [4]byte
			copy(addr[:], ipv4)
			if err := builder.AResource(resourceHeader, dnsmessage.AResource{A: addr}); err != nil {
				return nil, err
			}
		}
		if ipv6 := ip.To16(); question.Type == dnsmessage.TypeAAAA && ipv6 != nil && ip.To4() == nil {
			var addr [16]byte
			copy(addr[:], ipv6)
			if err := builder.AAAAResource(resourceHeader, dnsmessage.AAAAResource{AAAA: addr}); err != nil {
				return nil, err
			}
		}
	}

	return builder.Finish()
}

func startDiscardTCPServer(t *testing.T) net.Listener {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	t.Cleanup(func() {
		_ = listener.Close()
	})

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(io.Discard, c)
			}(conn)
		}
	}()

	return listener
}

func openConnectTunnel(t *testing.T, proxyAddr string, target string) (net.Conn, *bufio.Reader, *http.Response) {
	t.Helper()

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		conn.Close()
		t.Fatalf("Fprintf() error = %v", err)
	}

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		conn.Close()
		t.Fatalf("ReadResponse() error = %v", err)
	}

	return conn, reader, resp
}

func expectConnectionClose(t *testing.T, conn net.Conn, reader *bufio.Reader) {
	t.Helper()

	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}
	defer conn.SetReadDeadline(time.Time{})

	_, err := reader.ReadByte()
	if err == nil {
		t.Fatal("expected connection close")
	}
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		t.Fatalf("timed out waiting for connection close: %v", err)
	}
}

func mustTLSClientHello(t *testing.T, serverName string) []byte {
	t.Helper()

	recorder := &recordingConn{}
	client := tls.Client(recorder, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		ServerName:         serverName,
	})
	_ = client.Handshake()
	if recorder.Len() == 0 {
		t.Fatal("expected TLS client hello bytes")
	}
	return bytes.Clone(recorder.Bytes())
}

type recordingConn struct {
	bytes.Buffer
}

func (c *recordingConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *recordingConn) Write(p []byte) (int, error)      { return c.Buffer.Write(p) }
func (c *recordingConn) Close() error                     { return nil }
func (c *recordingConn) LocalAddr() net.Addr              { return recordingAddr("local") }
func (c *recordingConn) RemoteAddr() net.Addr             { return recordingAddr("remote") }
func (c *recordingConn) SetDeadline(time.Time) error      { return nil }
func (c *recordingConn) SetReadDeadline(time.Time) error  { return nil }
func (c *recordingConn) SetWriteDeadline(time.Time) error { return nil }

type recordingAddr string

func (a recordingAddr) Network() string { return "tcp" }
func (a recordingAddr) String() string  { return string(a) }

func init() {
	log.SetOutput(io.Discard)
}
