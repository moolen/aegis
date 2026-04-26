//go:build kind_e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"testing"
	"time"

	appmetrics "github.com/moolen/aegis/internal/metrics"
)

func TestKindAdminEnforcementOverride(t *testing.T) {
	h := newKindHarness(t)

	h.ApplyYAML(echoManifestYAML())
	h.WaitForDeploymentAvailable("echo", 3*time.Minute)
	h.RunDefaultCurlPod()

	h.HelmUpgradeInstall(kindAdminValuesYAML(h.namespace))
	h.RolloutRestartDeployment("aegis")
	h.WaitForDeploymentAvailable("aegis", 3*time.Minute)

	if got := h.ProxyStatusCode(kindCurlPodName, "/allowed"); got != "200" {
		t.Fatalf("initial allowed status = %q, want %q", got, "200")
	}
	if got := h.ProxyStatusCode(kindCurlPodName, "/denied"); got != "403" {
		t.Fatalf("initial denied status = %q, want %q", got, "403")
	}

	adminURL, stopForward := startKindPortForward(t, h, "deployment/aegis", 9091)
	defer stopForward()

	req, err := http.NewRequest(http.MethodGet, adminURL+"/admin/enforcement", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	unauthorized, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("unauthorized admin GET error = %v", err)
	}
	unauthorized.Body.Close()
	if unauthorized.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthorized admin status = %d, want %d", unauthorized.StatusCode, http.StatusUnauthorized)
	}

	status := kindAdminRequestStatus(t, adminURL, http.MethodGet, "", "")
	if status.Configured != "enforce" || status.Effective != "enforce" {
		t.Fatalf("initial enforcement status = %#v, want configured/effective enforce", status)
	}

	status = kindAdminRequestStatus(t, adminURL, http.MethodPost, "mode=audit", "")
	if status.Effective != "audit" || status.Override != "audit" {
		t.Fatalf("audit enforcement status = %#v, want effective+override audit", status)
	}

	waitFor(t, 30*time.Second, func() bool {
		return h.ProxyStatusCode(kindCurlPodName, "/denied") == "200"
	})

	metrics := h.Metrics(kindCurlPodName)
	if got := metricValue(t, metrics, "aegis_enforcement_mode", map[string]string{"scope": "effective", "mode": "audit"}); got != 1 {
		t.Fatalf("effective audit enforcement metric = %v, want 1", got)
	}

	status = kindAdminRequestStatus(t, adminURL, http.MethodPost, "mode=config", "")
	if status.Effective != "enforce" || status.Override != "" {
		t.Fatalf("config enforcement status = %#v, want effective enforce and cleared override", status)
	}

	waitFor(t, 30*time.Second, func() bool {
		return h.ProxyStatusCode(kindCurlPodName, "/denied") == "403"
	})
}

func kindAdminValuesYAML(namespace string) string {
	return `image:
  repository: aegis
  tag: e2e-kind
  pullPolicy: IfNotPresent
serviceAccount:
  create: true
  name: aegis
rbac:
  create: true
config:
  proxy:
    listen: ":3128"
  admin:
    enabled: true
    listen: "127.0.0.1:9091"
    token: "` + kindAdminToken + `"
  metrics:
    listen: ":9090"
  dns:
    cache_ttl: 30s
    timeout: 5s
    servers: []
    rebindingProtection:
      allowedHostPatterns: ["*.svc.cluster.local"]
  discovery:
    kubernetes:
      - name: kind-cluster
        auth:
          provider: inCluster
        namespaces: ["` + namespace + `"]
        resyncPeriod: 5s
  policies:
    - name: allow-http-admin
      subjects:
        kubernetes:
          discoveryNames: ["kind-cluster"]
          namespaces: ["` + namespace + `"]
          matchLabels: {}
      egress:
        - fqdn: "echo.` + namespace + `.svc.cluster.local"
          ports: [80]
          tls:
            mode: mitm
          http:
            allowedMethods: ["GET"]
            allowedPaths: ["/allowed"]
`
}

func kindAdminRequestStatus(t *testing.T, baseURL string, method string, query string, body string) appmetrics.EnforcementStatus {
	t.Helper()

	target := baseURL + "/admin/enforcement"
	if query != "" {
		target += "?" + query
	}
	req, err := http.NewRequest(method, target, strings.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+kindAdminToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s error = %v", method, target, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s %s status = %d, want %d", method, target, resp.StatusCode, http.StatusOK)
	}

	var status appmetrics.EnforcementStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	return status
}

func startKindPortForward(t *testing.T, h *kindHarness, target string, remotePort int) (string, func()) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	localPort := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(
		ctx,
		"kubectl",
		"--context",
		h.kubeContext,
		"-n",
		h.namespace,
		"port-forward",
		target,
		fmt.Sprintf("%d:%d", localPort, remotePort),
	)
	cmd.Dir = h.repoRoot
	var stderr bytes.Buffer
	cmd.Stdout = &stderr
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatalf("kubectl port-forward start error = %v", err)
	}

	baseURL := fmt.Sprintf("http://127.0.0.1:%d", localPort)
	waitFor(t, 10*time.Second, func() bool {
		req, err := http.NewRequest(http.MethodGet, baseURL+"/admin/enforcement", nil)
		if err != nil {
			return false
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == http.StatusUnauthorized
	})

	return baseURL, func() {
		cancel()
		_ = cmd.Wait()
		if t.Failed() && stderr.Len() > 0 {
			t.Logf("kubectl port-forward output:\n%s", stderr.String())
		}
	}
}
