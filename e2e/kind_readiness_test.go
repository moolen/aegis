//go:build kind_e2e

package e2e

import (
	"testing"
	"time"
)

func TestKindReadinessDegradesWhenDiscoveryIsInactive(t *testing.T) {
	t.Skip("provider stale/down readiness transitions are covered by package tests; the current Kubernetes watch-retry path does not produce a stable Kind-triggered stale transition for every-PR CI")

	h := newKindHarness(t)

	h.RunDefaultCurlPod()
	h.ApplyYAML(kindReadinessRBACYAML())

	h.HelmUpgradeInstall(kindReadinessValuesYAML(h.namespace))
	h.RolloutRestartDeployment("aegis")
	h.WaitForDeploymentAvailable("aegis", 3*time.Minute)

	if got := kindURLStatusCode(t, h, kindCurlPodName, "http://aegis:9090/healthz"); got != "200" {
		t.Fatalf("initial healthz status = %q, want %q", got, "200")
	}

	waitFor(t, 30*time.Second, func() bool {
		return kindURLStatusCode(t, h, kindCurlPodName, "http://aegis:9090/readyz") == "200"
	})

	waitFor(t, 7*time.Minute, func() bool {
		return kindURLStatusCode(t, h, kindCurlPodName, "http://aegis:9090/readyz") == "503"
	})

	if got := kindURLStatusCode(t, h, kindCurlPodName, "http://aegis:9090/healthz"); got != "200" {
		t.Fatalf("post-degradation healthz status = %q, want %q", got, "200")
	}

	metrics := h.Metrics(kindCurlPodName)
	if got := metricValue(t, metrics, "aegis_identity_provider_status", map[string]string{
		"provider": "readiness-cluster",
		"kind":     "kubernetes",
		"status":   "stale",
	}); got != 1 {
		t.Fatalf("stale readiness provider metric = %v, want 1", got)
	}
}

func kindReadinessRBACYAML() string {
	return `apiVersion: v1
kind: ServiceAccount
metadata:
  name: aegis-readiness
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: aegis-readiness
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: aegis-readiness
subjects:
  - kind: ServiceAccount
    name: aegis-readiness
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: aegis-readiness
`
}

func kindReadinessValuesYAML(namespace string) string {
	return `image:
  repository: aegis
  tag: e2e-kind
  pullPolicy: IfNotPresent
serviceAccount:
  create: false
  name: aegis-readiness
rbac:
  create: false
config:
  proxy:
    listen: ":3128"
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
      - name: readiness-cluster
        auth:
          provider: inCluster
        namespaces: ["` + namespace + `"]
        resyncPeriod: 5s
  policies:
    - name: readiness-placeholder
      subjects:
        kubernetes:
          discoveryNames: ["readiness-cluster"]
          namespaces: ["` + namespace + `"]
          matchLabels: {}
      egress:
        - fqdn: "example.invalid"
          ports: [80]
          tls:
            mode: mitm
          http:
            allowedMethods: ["GET"]
            allowedPaths: ["/"]
`
}
