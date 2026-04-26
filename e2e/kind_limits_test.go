//go:build kind_e2e

package e2e

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestKindConnectionLimits(t *testing.T) {
	h := newKindHarness(t)

	h.ApplyYAML(delayServerManifestYAML())
	h.WaitForDeploymentAvailable("delay-server", 3*time.Minute)

	h.DeletePodIfPresent(kindAllowedPod)
	h.CreateCurlPod(kindAllowedPod, "role=allowed")

	h.HelmUpgradeInstall(kindConnectionLimitValuesYAML(h.namespace))
	h.RolloutRestartDeployment("aegis")
	h.WaitForDeploymentAvailable("aegis", 3*time.Minute)

	waitFor(t, 30*time.Second, func() bool {
		metrics := h.Metrics(kindAllowedPod)
		active, activeOK := metricValueOrZero(metrics, "aegis_discovery_providers_active", map[string]string{})
		entries, entriesOK := metricValueOrZero(metrics, "aegis_identity_map_entries", map[string]string{
			"provider": "kind-cluster",
			"kind":     "kubernetes",
		})
		return activeOK && entriesOK && active == 1 && entries >= 1
	})

	firstDone := make(chan string, 1)
	firstErr := make(chan error, 1)
	var once sync.Once

	go func() {
		status, err := kindProxyStatusCodeForURL(h, kindAllowedPod, "http://delay-server."+h.namespace+".svc.cluster.local/delay/5")
		if err != nil {
			firstErr <- err
			return
		}
		firstDone <- status
	}()

	time.Sleep(750 * time.Millisecond)

	secondStatus, err := kindProxyStatusCodeForURL(h, kindAllowedPod, "http://delay-server."+h.namespace+".svc.cluster.local/delay/5")
	if err != nil {
		once.Do(func() {
			close(firstErr)
			close(firstDone)
		})
		t.Fatalf("second concurrent request error = %v", err)
	}
	if secondStatus != "429" {
		t.Fatalf("second concurrent request status = %q, want %q", secondStatus, "429")
	}

	var firstStatus string
	select {
	case err := <-firstErr:
		t.Fatalf("first concurrent request error = %v", err)
	case firstStatus = <-firstDone:
	case <-time.After(15 * time.Second):
		t.Fatal("timed out waiting for first concurrent request")
	}
	if firstStatus != "200" {
		t.Fatalf("first concurrent request status = %q, want %q", firstStatus, "200")
	}

	metrics := h.Metrics(kindAllowedPod)
	if got := metricValue(t, metrics, "aegis_identity_connection_limit_rejections_total", map[string]string{"protocol": "http"}); got != 1 {
		t.Fatalf("http connection limit rejection metric = %v, want 1", got)
	}
	if got := metricValue(t, metrics, "aegis_request_decisions_total", map[string]string{
		"protocol": "http",
		"action":   "deny",
		"policy":   "allow-httpbin-delay",
		"reason":   "connection_limit_exceeded",
	}); got != 1 {
		t.Fatalf("connection limit decision metric = %v, want 1", got)
	}
}

func kindConnectionLimitValuesYAML(namespace string) string {
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
    connectionLimits:
      maxConcurrentPerIdentity: 1
  admin:
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
    - name: allow-httpbin-delay
      subjects:
        kubernetes:
          discoveryNames: ["kind-cluster"]
          namespaces: ["` + namespace + `"]
          matchLabels:
            role: "allowed"
      egress:
        - fqdn: "delay-server.` + namespace + `.svc.cluster.local"
          ports: [80]
          tls:
            mode: mitm
          http:
            allowedMethods: ["GET"]
            allowedPaths: ["/delay/*"]
`
}

func delayServerManifestYAML() string {
	return `apiVersion: apps/v1
kind: Deployment
metadata:
  name: delay-server
spec:
  replicas: 1
  selector:
    matchLabels:
      app: delay-server
  template:
    metadata:
      labels:
        app: delay-server
    spec:
      containers:
        - name: delay-server
          image: python:3.12-alpine
          command:
            - python
            - -c
            - |
              import time
              from http.server import BaseHTTPRequestHandler, HTTPServer

              class Handler(BaseHTTPRequestHandler):
                  def do_GET(self):
                      if self.path.startswith("/delay/"):
                          try:
                              delay = float(self.path.rsplit("/", 1)[-1])
                          except ValueError:
                              delay = 0.0
                          time.sleep(delay)
                      body = b"ok"
                      self.send_response(200)
                      self.send_header("Content-Type", "text/plain")
                      self.send_header("Content-Length", str(len(body)))
                      self.end_headers()
                      self.wfile.write(body)

                  def log_message(self, format, *args):
                      return

              HTTPServer(("0.0.0.0", 80), Handler).serve_forever()
          ports:
            - containerPort: 80
---
apiVersion: v1
kind: Service
metadata:
  name: delay-server
spec:
  selector:
    app: delay-server
  ports:
    - port: 80
      targetPort: 80
`
}

func kindProxyStatusCodeForURL(h *kindHarness, podName string, targetURL string) (string, error) {
	output, err := tryKubectlExecPod(
		h.repoRoot,
		h.kubeContext,
		h.namespace,
		podName,
		"sh",
		"-c",
		fmt.Sprintf("curl -sS --proxy http://aegis:3128 -o /dev/null -w '%%{http_code}' %s", shellQuote(targetURL)),
	)
	if err != nil {
		return "", fmt.Errorf("proxy curl %s failed: %w\n%s", targetURL, err, output)
	}
	return strings.TrimSpace(output), nil
}
