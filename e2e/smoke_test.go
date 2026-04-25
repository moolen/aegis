//go:build e2e

package e2e

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	configpkg "github.com/moolen/aegis/internal/config"
)

var (
	buildOnce     sync.Once
	buildBinary   string
	buildRepoRoot string
	buildErr      error
)

func TestPolicyReloadAppliesWithoutRestart(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	proxyAddr := reserveTCPAddr(t)
	metricsAddr := reserveTCPAddr(t)
	configDir := t.TempDir()
	configPath := filepath.Join(configDir, "aegis.yaml")

	writeConfig(t, configPath, policyConfigYAML(proxyAddr, metricsAddr, "127.0.0.1", mustPort(t, upstreamURL.Host), "/allowed"))
	proc := startAegis(t, configPath)

	resp, err := proxiedRequest("http://"+proxyAddr, http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/allowed", mustPort(t, upstreamURL.Host)))
	if err != nil {
		t.Fatalf("proxiedRequest() initial error = %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("initial status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}

	writeConfig(t, configPath, policyConfigYAML(proxyAddr, metricsAddr, "127.0.0.1", mustPort(t, upstreamURL.Host), "/other"))
	if err := proc.signal(syscall.SIGHUP); err != nil {
		t.Fatalf("signal(SIGHUP) error = %v", err)
	}

	waitFor(t, 5*time.Second, func() bool {
		reloadedResp, reloadErr := proxiedRequest("http://"+proxyAddr, http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/allowed", mustPort(t, upstreamURL.Host)))
		if reloadErr != nil {
			return false
		}
		defer reloadedResp.Body.Close()
		return reloadedResp.StatusCode == http.StatusForbidden
	})

	metricsBody := fetchMetrics(t, "http://"+metricsAddr)
	if got := metricValue(t, metricsBody, "aegis_config_reloads_total", map[string]string{"result": "success"}); got != 1 {
		t.Fatalf("reload success metric = %v, want 1", got)
	}
}

func TestPolicyAuditModeAllowsDeniedHTTPRequests(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	proxyAddr := reserveTCPAddr(t)
	metricsAddr := reserveTCPAddr(t)
	configDir := t.TempDir()
	configPath := filepath.Join(configDir, "aegis.yaml")

	writeConfig(t, configPath, policyConfigYAMLWithEnforcement(proxyAddr, metricsAddr, "127.0.0.1", mustPort(t, upstreamURL.Host), "/other", "audit"))
	startAegis(t, configPath)

	resp, err := proxiedRequest("http://"+proxyAddr, http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/allowed", mustPort(t, upstreamURL.Host)))
	if err != nil {
		t.Fatalf("proxiedRequest() error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}

	metricsBody := fetchMetrics(t, "http://"+metricsAddr)
	if got := metricValue(t, metricsBody, "aegis_request_decisions_total", map[string]string{
		"protocol": "http",
		"action":   "allow",
		"policy":   "allow-http",
		"reason":   "audit_policy_denied",
	}); got != 1 {
		t.Fatalf("actual decision metric = %v, want 1", got)
	}
	if got := metricValue(t, metricsBody, "aegis_audit_decisions_total", map[string]string{
		"protocol": "http",
		"action":   "would_deny",
		"identity": "unknown",
		"fqdn":     "127.0.0.1",
		"policy":   "allow-http",
		"reason":   "policy_denied",
	}); got != 1 {
		t.Fatalf("audit decision metric = %v, want 1", got)
	}
}

func TestPolicyEnforcementBlocksDeniedHTTPRequests(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream should not be reached")
	}))
	defer upstream.Close()

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	proxyAddr := reserveTCPAddr(t)
	metricsAddr := reserveTCPAddr(t)
	configDir := t.TempDir()
	configPath := filepath.Join(configDir, "aegis.yaml")

	writeConfig(t, configPath, policyConfigYAMLWithOptions(proxyAddr, metricsAddr, "127.0.0.1", mustPort(t, upstreamURL.Host), "/other", policyConfigOptions{}))
	startAegis(t, configPath)

	resp, err := proxiedRequest("http://"+proxyAddr, http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/allowed", mustPort(t, upstreamURL.Host)))
	if err != nil {
		t.Fatalf("proxiedRequest() error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
}

func TestPolicyLevelAuditAllowsDeniedHTTPRequests(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	proxyAddr := reserveTCPAddr(t)
	metricsAddr := reserveTCPAddr(t)
	configDir := t.TempDir()
	configPath := filepath.Join(configDir, "aegis.yaml")

	writeConfig(t, configPath, policyConfigYAMLWithOptions(proxyAddr, metricsAddr, "127.0.0.1", mustPort(t, upstreamURL.Host), "/other", policyConfigOptions{PolicyEnforcement: "audit"}))
	startAegis(t, configPath)

	resp, err := proxiedRequest("http://"+proxyAddr, http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/allowed", mustPort(t, upstreamURL.Host)))
	if err != nil {
		t.Fatalf("proxiedRequest() error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}
}

func TestPolicyBypassAllowsDeniedHTTPRequests(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	proxyAddr := reserveTCPAddr(t)
	metricsAddr := reserveTCPAddr(t)
	configDir := t.TempDir()
	configPath := filepath.Join(configDir, "aegis.yaml")

	writeConfig(t, configPath, policyConfigYAMLWithOptions(proxyAddr, metricsAddr, "127.0.0.1", mustPort(t, upstreamURL.Host), "/other", policyConfigOptions{Bypass: true}))
	startAegis(t, configPath)

	resp, err := proxiedRequest("http://"+proxyAddr, http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/allowed", mustPort(t, upstreamURL.Host)))
	if err != nil {
		t.Fatalf("proxiedRequest() error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}

	metricsBody := fetchMetrics(t, "http://"+metricsAddr)
	if got := metricValue(t, metricsBody, "aegis_request_decisions_total", map[string]string{
		"protocol": "http",
		"action":   "allow",
		"policy":   "allow-http",
		"reason":   "audit_policy_denied",
	}); got != 1 {
		t.Fatalf("actual decision metric = %v, want 1", got)
	}
	if got := metricValue(t, metricsBody, "aegis_audit_decisions_total", map[string]string{
		"protocol": "http",
		"action":   "would_deny",
		"identity": "unknown",
		"fqdn":     "127.0.0.1",
		"policy":   "allow-http",
		"reason":   "policy_denied",
	}); got != 1 {
		t.Fatalf("audit decision metric = %v, want 1", got)
	}
}

func TestAdminEnforcementKillSwitchFlipsHTTPTrafficWithoutReload(t *testing.T) {
	const adminToken = "test-admin-token"

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	proxyAddr := reserveTCPAddr(t)
	metricsAddr := reserveTCPAddr(t)
	configDir := t.TempDir()
	configPath := filepath.Join(configDir, "aegis.yaml")

	writeConfig(t, configPath, policyConfigYAMLWithOptions(proxyAddr, metricsAddr, "127.0.0.1", mustPort(t, upstreamURL.Host), "/other", policyConfigOptions{AdminToken: adminToken}))
	startAegis(t, configPath)

	resp, err := proxiedRequest("http://"+proxyAddr, http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/allowed", mustPort(t, upstreamURL.Host)))
	if err != nil {
		t.Fatalf("proxiedRequest() initial error = %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("initial status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}

	adminResp, err := setAdminEnforcementMode("http://"+metricsAddr, adminToken, "audit")
	if err != nil {
		t.Fatalf("setAdminEnforcementMode(audit) error = %v", err)
	}
	adminResp.Body.Close()
	if adminResp.StatusCode != http.StatusOK {
		t.Fatalf("admin audit status = %d, want %d", adminResp.StatusCode, http.StatusOK)
	}

	waitFor(t, 5*time.Second, func() bool {
		auditResp, auditErr := proxiedRequest("http://"+proxyAddr, http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/allowed", mustPort(t, upstreamURL.Host)))
		if auditErr != nil {
			return false
		}
		defer auditResp.Body.Close()
		return auditResp.StatusCode == http.StatusNoContent
	})

	metricsBody := fetchMetrics(t, "http://"+metricsAddr)
	if got := metricValue(t, metricsBody, "aegis_enforcement_mode", map[string]string{"scope": "effective", "mode": "audit"}); got != 1 {
		t.Fatalf("effective audit mode gauge = %v, want 1", got)
	}

	adminResp, err = setAdminEnforcementMode("http://"+metricsAddr, adminToken, "config")
	if err != nil {
		t.Fatalf("setAdminEnforcementMode(config) error = %v", err)
	}
	adminResp.Body.Close()
	if adminResp.StatusCode != http.StatusOK {
		t.Fatalf("admin config status = %d, want %d", adminResp.StatusCode, http.StatusOK)
	}

	waitFor(t, 5*time.Second, func() bool {
		enforceResp, enforceErr := proxiedRequest("http://"+proxyAddr, http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/allowed", mustPort(t, upstreamURL.Host)))
		if enforceErr != nil {
			return false
		}
		defer enforceResp.Body.Close()
		return enforceResp.StatusCode == http.StatusForbidden
	})
}

func TestUnknownIdentityDenyBlocksHTTPRequests(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream should not be reached")
	}))
	defer upstream.Close()

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	proxyAddr := reserveTCPAddr(t)
	metricsAddr := reserveTCPAddr(t)
	configDir := t.TempDir()
	configPath := filepath.Join(configDir, "aegis.yaml")

	writeConfig(t, configPath, policyConfigYAMLWithOptions(proxyAddr, metricsAddr, "127.0.0.1", mustPort(t, upstreamURL.Host), "/allowed", policyConfigOptions{UnknownIdentityPolicy: "deny"}))
	startAegis(t, configPath)

	resp, err := proxiedRequest("http://"+proxyAddr, http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/allowed", mustPort(t, upstreamURL.Host)))
	if err != nil {
		t.Fatalf("proxiedRequest() error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
}

func TestHTTPConnectionLimitRejectsSecondConcurrentRequest(t *testing.T) {
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

	proxyAddr := reserveTCPAddr(t)
	metricsAddr := reserveTCPAddr(t)
	configDir := t.TempDir()
	configPath := filepath.Join(configDir, "aegis.yaml")

	writeConfig(t, configPath, policyConfigYAMLWithOptions(proxyAddr, metricsAddr, "127.0.0.1", mustPort(t, upstreamURL.Host), "/allowed", policyConfigOptions{MaxConcurrentPerIdentity: 1}))
	startAegis(t, configPath)

	firstRespCh := make(chan *http.Response, 1)
	firstErrCh := make(chan error, 1)
	go func() {
		resp, reqErr := proxiedRequest("http://"+proxyAddr, http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/allowed", mustPort(t, upstreamURL.Host)))
		if reqErr != nil {
			firstErrCh <- reqErr
			return
		}
		firstRespCh <- resp
	}()

	select {
	case <-upstreamStarted:
	case err := <-firstErrCh:
		t.Fatalf("first proxiedRequest() error = %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for first request to hit upstream")
	}

	secondResp, err := proxiedRequest("http://"+proxyAddr, http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/allowed", mustPort(t, upstreamURL.Host)))
	if err != nil {
		t.Fatalf("second proxiedRequest() error = %v", err)
	}
	defer secondResp.Body.Close()
	if secondResp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second status = %d, want %d", secondResp.StatusCode, http.StatusTooManyRequests)
	}

	close(releaseUpstream)

	select {
	case firstResp := <-firstRespCh:
		defer firstResp.Body.Close()
		if firstResp.StatusCode != http.StatusNoContent {
			t.Fatalf("first status = %d, want %d", firstResp.StatusCode, http.StatusNoContent)
		}
	case err := <-firstErrCh:
		t.Fatalf("first proxiedRequest() error = %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for first response")
	}

	metricsBody := fetchMetrics(t, "http://"+metricsAddr)
	if got := metricValue(t, metricsBody, "aegis_identity_connection_limit_rejections_total", map[string]string{"protocol": "http"}); got != 1 {
		t.Fatalf("http limit rejection metric = %v, want 1", got)
	}
	if got := metricValue(t, metricsBody, "aegis_request_decisions_total", map[string]string{
		"protocol": "http",
		"action":   "deny",
		"policy":   "allow-http",
		"reason":   "connection_limit_exceeded",
	}); got != 1 {
		t.Fatalf("deny decision metric = %v, want 1", got)
	}
}

func TestMITMCARotationIsVisibleInMetrics(t *testing.T) {
	proxyAddr := reserveTCPAddr(t)
	metricsAddr := reserveTCPAddr(t)
	configDir := t.TempDir()
	configPath := filepath.Join(configDir, "aegis.yaml")

	certA, keyA := writeTestCAFiles(t, configDir, "Aegis E2E CA A")
	certB, keyB := writeTestCAFiles(t, configDir, "Aegis E2E CA B")

	writeConfig(t, configPath, mitmConfigYAML(proxyAddr, metricsAddr, certA, keyA))
	proc := startAegis(t, configPath)

	initialMetrics := fetchMetrics(t, "http://"+metricsAddr)
	if got := metricValue(t, initialMetrics, "aegis_mitm_ca_cycles_total", map[string]string{"result": "initial"}); got != 1 {
		t.Fatalf("initial mitm ca metric = %v, want 1", got)
	}

	writeConfig(t, configPath, mitmConfigYAML(proxyAddr, metricsAddr, certB, keyB))
	if err := proc.signal(syscall.SIGHUP); err != nil {
		t.Fatalf("signal(SIGHUP) error = %v", err)
	}

	waitFor(t, 5*time.Second, func() bool {
		metricsBody := fetchMetrics(t, "http://"+metricsAddr)
		value, ok := metricValueOrZero(metricsBody, "aegis_mitm_ca_cycles_total", map[string]string{"result": "rotated"})
		return ok && value == 1
	})

	metricsBody := fetchMetrics(t, "http://"+metricsAddr)
	if got := metricValue(t, metricsBody, "aegis_config_reloads_total", map[string]string{"result": "success"}); got != 1 {
		t.Fatalf("reload success metric = %v, want 1", got)
	}
	if got := metricValue(t, metricsBody, "aegis_mitm_ca_cycles_total", map[string]string{"result": "rotated"}); got != 1 {
		t.Fatalf("rotated mitm ca metric = %v, want 1\nmetrics:\n%s", got, metricsBody)
	}
}

type aegisProcess struct {
	cmd    *exec.Cmd
	logBuf *bytes.Buffer
}

func startAegis(t *testing.T, configPath string) *aegisProcess {
	t.Helper()

	return startAegisWithEnv(t, configPath, nil)
}

func startAegisWithEnv(t *testing.T, configPath string, extraEnv []string) *aegisProcess {
	t.Helper()

	binary, repoRoot := ensureBinaryBuilt(t)
	cmd := exec.Command(binary, "-config", configPath)
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(), extraEnv...)
	var logBuf bytes.Buffer
	cmd.Stdout = &logBuf
	cmd.Stderr = &logBuf

	if err := cmd.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	proc := &aegisProcess{cmd: cmd, logBuf: &logBuf}
	t.Cleanup(func() {
		proc.stop(t)
	})

	cfgBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	metricsAddr := parseMetricsAddr(t, string(cfgBytes))
	waitFor(t, 10*time.Second, func() bool {
		resp, getErr := http.Get("http://" + metricsAddr + "/readyz")
		if getErr != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	})

	return proc
}

func (p *aegisProcess) signal(sig syscall.Signal) error {
	return p.cmd.Process.Signal(sig)
}

func (p *aegisProcess) stop(t *testing.T) {
	t.Helper()

	if p.cmd.ProcessState != nil && p.cmd.ProcessState.Exited() {
		return
	}

	_ = p.cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan error, 1)
	go func() {
		done <- p.cmd.Wait()
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("aegis exited with error: %v\nlogs:\n%s", err, p.logBuf.String())
		}
	case <-time.After(10 * time.Second):
		_ = p.cmd.Process.Kill()
		_, _ = io.Copy(io.Discard, p.logBuf)
		t.Fatalf("timed out stopping aegis\nlogs:\n%s", p.logBuf.String())
	}
}

func ensureBinaryBuilt(t *testing.T) (string, string) {
	t.Helper()

	buildOnce.Do(func() {
		wd, err := os.Getwd()
		if err != nil {
			buildErr = err
			return
		}
		buildRepoRoot = filepath.Dir(wd)
		tempDir, err := os.MkdirTemp("", "aegis-e2e-*")
		if err != nil {
			buildErr = err
			return
		}
		buildBinary = filepath.Join(tempDir, "aegis")
		cmd := exec.Command("go", "build", "-o", buildBinary, "./cmd/aegis")
		cmd.Dir = buildRepoRoot
		output, err := cmd.CombinedOutput()
		if err != nil {
			buildErr = fmt.Errorf("build aegis binary: %w: %s", err, string(output))
		}
	})

	if buildErr != nil {
		t.Fatalf("ensureBinaryBuilt() error = %v", buildErr)
	}

	return buildBinary, buildRepoRoot
}

func reserveTCPAddr(t *testing.T) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	addr := listener.Addr().String()
	listener.Close()
	return addr
}

func proxiedRequest(proxyAddr string, method string, target string) (*http.Response, error) {
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: func(*http.Request) (*url.URL, error) {
				return url.Parse(proxyAddr)
			},
		},
	}

	req, err := http.NewRequest(method, target, nil)
	if err != nil {
		return nil, err
	}

	return client.Do(req)
}

func fetchMetrics(t *testing.T, baseURL string) string {
	t.Helper()

	resp, err := http.Get(baseURL + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics error = %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}

	return string(body)
}

func setAdminEnforcementMode(baseURL string, token string, mode string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPost, baseURL+"/admin/enforcement?mode="+mode, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return http.DefaultClient.Do(req)
}

func writeConfig(t *testing.T, path string, contents string) {
	t.Helper()

	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
}

func policyConfigYAML(proxyAddr string, metricsAddr string, host string, port int, allowedPath string) string {
	return policyConfigYAMLWithOptions(proxyAddr, metricsAddr, host, port, allowedPath, policyConfigOptions{})
}

func policyConfigYAMLWithEnforcement(proxyAddr string, metricsAddr string, host string, port int, allowedPath string, enforcement string) string {
	return policyConfigYAMLWithOptions(proxyAddr, metricsAddr, host, port, allowedPath, policyConfigOptions{Enforcement: enforcement})
}

type policyConfigOptions struct {
	Enforcement              string
	PolicyEnforcement        string
	Bypass                   bool
	AdminToken               string
	UnknownIdentityPolicy    string
	MaxConcurrentPerIdentity int
}

func policyConfigYAMLWithOptions(proxyAddr string, metricsAddr string, host string, port int, allowedPath string, opts policyConfigOptions) string {
	enforcementBlock := ""
	if opts.Enforcement != "" {
		enforcementBlock = "  enforcement: " + opts.Enforcement + "\n"
	}
	connectionLimitBlock := ""
	if opts.MaxConcurrentPerIdentity > 0 {
		connectionLimitBlock = fmt.Sprintf("  connectionLimits:\n    maxConcurrentPerIdentity: %d\n", opts.MaxConcurrentPerIdentity)
	}
	unknownIdentityBlock := ""
	if opts.UnknownIdentityPolicy != "" {
		unknownIdentityBlock = "  unknownIdentityPolicy: " + opts.UnknownIdentityPolicy + "\n"
	}
	bypassBlock := ""
	if opts.Bypass {
		bypassBlock = "    bypass: true\n"
	}
	policyEnforcementBlock := ""
	if opts.PolicyEnforcement != "" {
		policyEnforcementBlock = "    enforcement: " + opts.PolicyEnforcement + "\n"
	}
	adminBlock := ""
	if opts.AdminToken != "" {
		adminBlock = fmt.Sprintf("admin:\n  token: %q\n", opts.AdminToken)
	}

	return fmt.Sprintf(`proxy:
  listen: "%s"
%s%s%smetrics:
  listen: "%s"
%sdns:
  cache_ttl: 30s
  timeout: 5s
  servers: []
  rebindingProtection:
    allowedCIDRs: ["127.0.0.0/8"]
policies:
  - name: allow-http
%s%s    identitySelector:
      matchLabels: {}
    egress:
      - fqdn: "%s"
        ports: [%d]
        tls:
          mode: mitm
        http:
          allowedMethods: ["GET"]
          allowedPaths: ["%s"]
`, proxyAddr, enforcementBlock, unknownIdentityBlock, connectionLimitBlock, metricsAddr, adminBlock, bypassBlock, policyEnforcementBlock, host, port, allowedPath)
}

func mitmConfigYAML(proxyAddr string, metricsAddr string, certFile string, keyFile string) string {
	return fmt.Sprintf(`proxy:
  listen: "%s"
  ca:
    certFile: "%s"
    keyFile: "%s"
metrics:
  listen: "%s"
dns:
  cache_ttl: 30s
  timeout: 5s
  servers: []
  rebindingProtection:
    allowedCIDRs: ["127.0.0.0/8"]
policies:
  - name: allow-mitm
    identitySelector:
      matchLabels: {}
    egress:
      - fqdn: "example.com"
        ports: [443]
        tls:
          mode: mitm
        http:
          allowedMethods: ["GET"]
          allowedPaths: ["/*"]
`, proxyAddr, certFile, keyFile, metricsAddr)
}

func writeTestCAFiles(t *testing.T, dir string, commonName string) (string, string) {
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

	certFile := filepath.Join(dir, commonName+".crt")
	keyFile := filepath.Join(dir, commonName+".key")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatalf("WriteFile(cert) error = %v", err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}), 0o600); err != nil {
		t.Fatalf("WriteFile(key) error = %v", err)
	}

	return certFile, keyFile
}

func parseMetricsAddr(t *testing.T, config string) string {
	t.Helper()

	cfg, err := configpkg.Load(bytes.NewBufferString(config))
	if err != nil {
		t.Fatalf("config.Load() error = %v", err)
	}
	return cfg.Metrics.Listen
}

func mustPort(t *testing.T, hostport string) int {
	t.Helper()

	_, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		t.Fatalf("SplitHostPort() error = %v", err)
	}

	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		t.Fatalf("Sscanf() error = %v", err)
	}
	return port
}
