//go:build kind_e2e

package e2e

import (
	"testing"
	"time"
)

func TestKindHTTPAllowDeny(t *testing.T) {
	h := newKindHarness(t)

	h.ApplyYAML(echoManifestYAML())
	h.WaitForDeploymentAvailable("echo", 3*time.Minute)
	h.RunDefaultCurlPod()

	h.HelmUpgradeInstall(kindHTTPValuesYAML(h.namespace))
	h.RolloutRestartDeployment("aegis")
	h.WaitForDeploymentAvailable("aegis", 3*time.Minute)

	if got := h.ProxyStatusCode(kindCurlPodName, "/allowed"); got != "200" {
		t.Fatalf("allowed HTTP status = %q, want %q", got, "200")
	}
	if got := h.ProxyStatusCode(kindCurlPodName, "/denied"); got != "403" {
		t.Fatalf("denied HTTP status = %q, want %q", got, "403")
	}

	metrics := h.Metrics(kindCurlPodName)
	if got := metricValue(t, metrics, "aegis_request_decisions_total", map[string]string{
		"protocol": "http",
		"action":   "allow",
		"policy":   "allow-http-path",
		"reason":   "policy_allowed",
	}); got != 1 {
		t.Fatalf("http allow metric = %v, want 1", got)
	}
	if got := metricValue(t, metrics, "aegis_request_decisions_total", map[string]string{
		"protocol": "http",
		"action":   "deny",
		"policy":   "allow-http-path",
		"reason":   "policy_denied",
	}); got != 1 {
		t.Fatalf("http deny metric = %v, want 1", got)
	}
}

func kindHTTPValuesYAML(namespace string) string {
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
    - name: allow-http-path
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
