//go:build kind_e2e

package e2e

import (
	"fmt"
	"testing"
	"time"
)

func TestKindMITMInnerHTTPAllowDeny(t *testing.T) {
	h := newKindHarness(t)

	const (
		deploymentName = "tls-mitm"
		serviceName    = "tls-mitm"
		proxyCASecret  = "aegis-proxy-ca"
	)

	host := fmt.Sprintf("%s.%s.svc.cluster.local", serviceName, h.namespace)
	assets := newKindTLSAssets(t, []string{host})

	h.ApplyYAML(kindMITMScenarioManifestYAML(deploymentName, serviceName, proxyCASecret, assets))
	h.WaitForDeploymentAvailable(deploymentName, 3*time.Minute)
	h.RunDefaultCurlPod()

	h.HelmUpgradeInstall(kindMITMValuesYAML(h.namespace, host, proxyCASecret))
	runCommand(t, h.repoRoot, kindDefaultTimeout, "kubectl", "--context", h.kubeContext, "-n", h.namespace, "set", "env", "deployment/aegis", "SSL_CERT_FILE=/etc/aegis/ca/ca.crt")
	h.WaitForDeploymentAvailable("aegis", 3*time.Minute)

	if got := kindHTTPSProxyStatusCode(h, kindCurlPodName, host, "/allowed"); got != "200" {
		t.Fatalf("allowed MITM status = %q, want %q", got, "200")
	}
	if got := kindHTTPSProxyStatusCode(h, kindCurlPodName, host, "/denied"); got != "403" {
		t.Fatalf("denied MITM status = %q, want %q", got, "403")
	}

	metrics := h.Metrics(kindCurlPodName)
	if got := metricValue(t, metrics, "aegis_request_decisions_total", map[string]string{
		"protocol": "mitm_http",
		"action":   "allow",
		"policy":   "allow-mitm-path",
		"reason":   "policy_allowed",
	}); got != 1 {
		t.Fatalf("mitm allow metric = %v, want 1", got)
	}
	if got := metricValue(t, metrics, "aegis_request_decisions_total", map[string]string{
		"protocol": "mitm_http",
		"action":   "deny",
		"policy":   "allow-mitm-path",
		"reason":   "policy_denied",
	}); got != 1 {
		t.Fatalf("mitm deny metric = %v, want 1", got)
	}
}

func kindMITMScenarioManifestYAML(deploymentName string, serviceName string, proxyCASecret string, assets kindTLSAssets) string {
	return kindProxyCASecretYAML(proxyCASecret, assets) + "\n---\n" + kindTLSEchoManifestYAML(deploymentName, []string{serviceName}, assets)
}

func kindProxyCASecretYAML(secretName string, assets kindTLSAssets) string {
	return fmt.Sprintf(`apiVersion: v1
kind: Secret
metadata:
  name: %s
type: Opaque
stringData:
  ca.crt: |
%s
  ca.key: |
%s
`, secretName, indentYAMLBlock(assets.caCertPEM, 4), indentYAMLBlock(assets.caKeyPEM, 4))
}

func kindMITMValuesYAML(namespace string, host string, proxyCASecret string) string {
	return `image:
  repository: aegis
  tag: e2e-kind
  pullPolicy: IfNotPresent
serviceAccount:
  create: true
  name: aegis
rbac:
  create: true
proxyCA:
  existingSecret: "` + proxyCASecret + `"
  mountPath: /etc/aegis/ca
  certFile: ca.crt
  keyFile: ca.key
config:
  proxy:
    listen: ":3128"
    ca:
      certFile: /etc/aegis/ca/ca.crt
      keyFile: /etc/aegis/ca/ca.key
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
    - name: allow-mitm-path
      subjects:
        kubernetes:
          discoveryNames: ["kind-cluster"]
          namespaces: ["` + namespace + `"]
          matchLabels: {}
      egress:
        - fqdn: "` + host + `"
          ports: [443]
          tls:
            mode: mitm
          http:
            allowedMethods: ["GET"]
            allowedPaths: ["/allowed"]
`
}
