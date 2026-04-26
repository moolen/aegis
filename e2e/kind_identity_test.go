//go:build kind_e2e

package e2e

import (
	"testing"
	"time"
)

func TestKindKubernetesDiscoveryIdentityEnforcement(t *testing.T) {
	h := newKindHarness(t)

	h.ApplyYAML(echoManifestYAML())
	h.WaitForDeploymentAvailable("echo", 3*time.Minute)

	h.DeletePodIfPresent(kindAllowedPod)
	h.DeletePodIfPresent(kindDeniedPod)
	h.CreateCurlPod(kindAllowedPod, "role=allowed")
	h.CreateCurlPod(kindDeniedPod, "role=denied")

	h.HelmUpgradeInstall(kindIdentityScenarioValuesYAML(h.namespace))
	h.RolloutRestartDeployment("aegis")
	h.WaitForDeploymentAvailable("aegis", 3*time.Minute)

	waitFor(t, 30*time.Second, func() bool {
		metrics := h.Metrics(kindAllowedPod)
		active, activeOK := metricValueOrZero(metrics, "aegis_discovery_providers_active", map[string]string{})
		entries, entriesOK := metricValueOrZero(metrics, "aegis_identity_map_entries", map[string]string{
			"provider": "kind-cluster",
			"kind":     "kubernetes",
		})
		return activeOK && entriesOK && active == 1 && entries >= 2
	})

	allowedIP := h.PodIP(kindAllowedPod)
	deniedIP := h.PodIP(kindDeniedPod)

	if got := h.ProxyStatusCode(kindAllowedPod, "/allowed"); got != "200" {
		t.Fatalf("allowed identity status = %q, want %q", got, "200")
	}
	if got := h.ProxyStatusCode(kindDeniedPod, "/allowed"); got != "403" {
		t.Fatalf("denied identity status = %q, want %q", got, "403")
	}

	if allowedIP == deniedIP {
		t.Fatalf("allowed and denied pod IPs are identical: %q", allowedIP)
	}
}

func kindIdentityScenarioValuesYAML(namespace string) string {
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
  shutdown:
    gracePeriod: 10s
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
    - name: allow-echo-from-allowed
      subjects:
        kubernetes:
          discoveryNames: ["kind-cluster"]
          namespaces: ["` + namespace + `"]
          matchLabels:
            role: "allowed"
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
