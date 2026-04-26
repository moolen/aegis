//go:build kind_e2e

package e2e

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestKindReloadAppliesRuntimeConfigChanges(t *testing.T) {
	h := newKindHarness(t)

	h.ApplyYAML(kindReloadUpstreamManifestYAML())
	h.WaitForDeploymentAvailable("echo", 3*time.Minute)
	h.RunDefaultCurlPod()

	sourceIP := h.PodIP(kindCurlPodName)
	sourceCIDR := kindHostCIDR(t, sourceIP)

	h.HelmUpgradeInstall(kindReloadValuesYAML(h.namespace, sourceCIDR, "/"))
	h.WaitForDeploymentAvailable("aegis", 3*time.Minute)

	aegisPod := kindDeploymentPodName(t, h, "aegis")
	adminURL, stopForward := startKindPortForward(t, h, "deployment/aegis", 9091)
	defer stopForward()

	if got := kindURLStatusCode(t, h, kindCurlPodName, "http://aegis:9090/healthz"); got != "200" {
		t.Fatalf("initial healthz status = %q, want %q", got, "200")
	}
	if got := kindURLStatusCode(t, h, kindCurlPodName, "http://aegis:9090/readyz"); got != "200" {
		t.Fatalf("initial readyz status = %q, want %q", got, "200")
	}
	if got := h.ProxyStatusCode(kindCurlPodName, "/"); got != "200" {
		t.Fatalf("initial allowed status = %q, want %q", got, "200")
	}
	if got := h.ProxyStatusCode(kindCurlPodName, "/other"); got != "403" {
		t.Fatalf("initial other status = %q, want %q", got, "403")
	}

	updatedConfig := kindReloadConfigYAML(h.namespace, sourceCIDR, "/other")
	h.ApplyYAML(kindAegisConfigMapManifest(updatedConfig))

	waitFor(t, 120*time.Second, func() bool {
		if err := triggerKindAdminReload(adminURL); err != nil {
			t.Logf("reload signal failed: %v", err)
			return false
		}
		if h.ProxyStatusCode(kindCurlPodName, "/") != "403" {
			return false
		}
		if h.ProxyStatusCode(kindCurlPodName, "/other") != "200" {
			return false
		}

		metrics := h.Metrics(kindCurlPodName)
		reloads, ok := metricValueOrZero(metrics, "aegis_config_reloads_total", map[string]string{"result": "success"})
		return ok && reloads >= 1
	})

	if got := kindURLStatusCode(t, h, kindCurlPodName, "http://aegis:9090/healthz"); got != "200" {
		t.Fatalf("post-reload healthz status = %q, want %q", got, "200")
	}
	if got := kindURLStatusCode(t, h, kindCurlPodName, "http://aegis:9090/readyz"); got != "200" {
		t.Fatalf("post-reload readyz status = %q, want %q", got, "200")
	}
	if got := kindDeploymentPodName(t, h, "aegis"); got != aegisPod {
		t.Fatalf("aegis pod = %q after reload, want unchanged pod %q", got, aegisPod)
	}
}

func kindReloadUpstreamManifestYAML() string {
	return `apiVersion: v1
kind: ConfigMap
metadata:
  name: echo-nginx
data:
  nginx.conf: |
    events {}
    http {
      server {
        listen 8080;
        location / {
          default_type text/plain;
          return 200 "ok";
        }
      }
    }
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: echo
spec:
  replicas: 1
  selector:
    matchLabels:
      app: echo
  template:
    metadata:
      labels:
        app: echo
    spec:
      containers:
        - name: nginx
          image: nginx:1.27-alpine
          ports:
            - containerPort: 8080
          volumeMounts:
            - name: config
              mountPath: /etc/nginx/nginx.conf
              subPath: nginx.conf
              readOnly: true
      volumes:
        - name: config
          configMap:
            name: echo-nginx
---
apiVersion: v1
kind: Service
metadata:
  name: echo
spec:
  selector:
    app: echo
  ports:
    - port: 80
      targetPort: 8080
`
}

func kindReloadValuesYAML(namespace string, cidr string, allowedPath string) string {
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
  policies:
    - name: allow-reload-path
      subjects:
        cidrs: ["` + cidr + `"]
      egress:
        - fqdn: "echo.` + namespace + `.svc.cluster.local"
          ports: [80]
          tls:
            mode: mitm
          http:
            allowedMethods: ["GET"]
            allowedPaths: ["` + allowedPath + `"]
`
}

func kindReloadConfigYAML(namespace string, cidr string, allowedPath string) string {
	return `proxy:
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
policies:
  - name: allow-reload-path
    subjects:
      cidrs: ["` + cidr + `"]
    egress:
      - fqdn: "echo.` + namespace + `.svc.cluster.local"
        ports: [80]
        tls:
          mode: mitm
        http:
          allowedMethods: ["GET"]
          allowedPaths: ["` + allowedPath + `"]
`
}

func kindAegisConfigMapManifest(configYAML string) string {
	return "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: aegis-config\ndata:\n  aegis.yaml: |\n" + indentYAML(configYAML, "    ")
}

func triggerKindAdminReload(adminURL string) error {
	req, err := http.NewRequest(http.MethodPost, adminURL+"/admin/reload", nil)
	if err != nil {
		return fmt.Errorf("NewRequest() error = %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+kindAdminToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("POST /admin/reload error = %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("POST /admin/reload status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}
	return nil
}

func kindDeploymentPodName(t *testing.T, h *kindHarness, deployment string) string {
	t.Helper()

	return strings.TrimSpace(runCommand(
		t,
		h.repoRoot,
		30*time.Second,
		"kubectl",
		"--context",
		h.kubeContext,
		"-n",
		h.namespace,
		"get",
		"pods",
		"-l",
		"app.kubernetes.io/name="+deployment,
		"-o",
		"jsonpath={.items[0].metadata.name}",
	))
}

func kindURLStatusCode(t *testing.T, h *kindHarness, podName string, targetURL string) string {
	t.Helper()

	return strings.TrimSpace(h.ExecPod(
		podName,
		"sh",
		"-c",
		fmt.Sprintf("curl -sS -o /dev/null -w '%%{http_code}' %s", shellQuote(targetURL)),
	))
}

func indentYAML(value string, prefix string) string {
	lines := strings.Split(strings.TrimSuffix(value, "\n"), "\n")
	for i, line := range lines {
		lines[i] = prefix + line
	}
	return strings.Join(lines, "\n") + "\n"
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'"
}
