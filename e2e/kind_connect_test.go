//go:build kind_e2e

package e2e

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestKindCONNECTPassthroughAllowDeny(t *testing.T) {
	h := newKindHarness(t)

	const (
		deploymentName = "tls-connect"
		allowedService = "tls-connect-allowed"
		deniedService  = "tls-connect-denied"
	)

	allowedHost := fmt.Sprintf("%s.%s.svc.cluster.local", allowedService, h.namespace)
	deniedHost := fmt.Sprintf("%s.%s.svc.cluster.local", deniedService, h.namespace)
	assets := newKindTLSAssets(t, []string{allowedHost, deniedHost})

	h.ApplyYAML(kindTLSEchoManifestYAML(deploymentName, []string{allowedService, deniedService}, assets))
	h.WaitForDeploymentAvailable(deploymentName, 3*time.Minute)
	h.RunDefaultCurlPod()

	h.HelmUpgradeInstall(kindCONNECTValuesYAML(h.namespace, allowedHost))
	h.RolloutRestartDeployment("aegis")
	h.WaitForDeploymentAvailable("aegis", 3*time.Minute)

	if got := kindHTTPSProxyStatusCode(h, kindCurlPodName, allowedHost, "/"); got == "000" || got == "403" {
		t.Fatalf("allowed CONNECT status = %q, want successful non-proxy-denied tunnel", got)
	}

	deniedAttempt := kindHTTPSProxyAttempt(h, kindCurlPodName, deniedHost, "/")
	if !strings.Contains(deniedAttempt, "response 403") {
		t.Fatalf("denied CONNECT output = %q, want proxy 403", deniedAttempt)
	}

	metrics := h.Metrics(kindCurlPodName)
	if got := metricValue(t, metrics, "aegis_connect_tunnels_total", map[string]string{
		"mode":   "passthrough",
		"result": "established",
	}); got != 1 {
		t.Fatalf("connect established metric = %v, want 1", got)
	}
	if got := metricValue(t, metrics, "aegis_request_decisions_total", map[string]string{
		"protocol": "connect",
		"action":   "deny",
		"policy":   "allow-connect-target",
		"reason":   "policy_denied",
	}); got != 1 {
		t.Fatalf("connect deny metric = %v, want 1", got)
	}
}

type kindTLSAssets struct {
	caCertPEM     string
	caKeyPEM      string
	serverCertPEM string
	serverKeyPEM  string
}

func newKindTLSAssets(t *testing.T, hosts []string) kindTLSAssets {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(ca) error = %v", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Aegis Kind E2E CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caKey.Public(), caKey)
	if err != nil {
		t.Fatalf("CreateCertificate(ca) error = %v", err)
	}

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(server) error = %v", err)
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: hosts[0],
		},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    hosts,
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caTemplate, serverKey.Public(), caKey)
	if err != nil {
		t.Fatalf("CreateCertificate(server) error = %v", err)
	}

	return kindTLSAssets{
		caCertPEM:     string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})),
		caKeyPEM:      string(mustMarshalECKey(t, caKey)),
		serverCertPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER})),
		serverKeyPEM:  string(mustMarshalECKey(t, serverKey)),
	}
}

func mustMarshalECKey(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()

	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey() error = %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
}

func kindTLSEchoManifestYAML(deploymentName string, serviceNames []string, assets kindTLSAssets) string {
	secretName := deploymentName + "-tls"
	configMapName := deploymentName + "-nginx"

	var services strings.Builder
	for _, serviceName := range serviceNames {
		fmt.Fprintf(&services, `---
apiVersion: v1
kind: Service
metadata:
  name: %s
spec:
  selector:
    app: %s
  ports:
    - port: 443
      targetPort: 8443
`, serviceName, deploymentName)
	}

	return fmt.Sprintf(`apiVersion: v1
kind: Secret
metadata:
  name: %s
type: kubernetes.io/tls
stringData:
  tls.crt: |
%s
  tls.key: |
%s
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: %s
data:
  nginx.conf: |
    events {}
    http {
      server {
        listen 8443 ssl;
        ssl_certificate /etc/nginx/tls/tls.crt;
        ssl_certificate_key /etc/nginx/tls/tls.key;
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
  name: %s
spec:
  replicas: 1
  selector:
    matchLabels:
      app: %s
  template:
    metadata:
      labels:
        app: %s
    spec:
      containers:
        - name: nginx
          image: nginx:1.27-alpine
          ports:
            - containerPort: 8443
          volumeMounts:
            - name: tls
              mountPath: /etc/nginx/tls
              readOnly: true
            - name: config
              mountPath: /etc/nginx/nginx.conf
              subPath: nginx.conf
              readOnly: true
      volumes:
        - name: tls
          secret:
            secretName: %s
        - name: config
          configMap:
            name: %s
%s`, secretName, indentYAMLBlock(assets.serverCertPEM, 4), indentYAMLBlock(assets.serverKeyPEM, 4), configMapName, deploymentName, deploymentName, deploymentName, secretName, configMapName, services.String())
}

func kindCONNECTValuesYAML(namespace string, allowedHost string) string {
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
    - name: allow-connect-target
      subjects:
        kubernetes:
          discoveryNames: ["kind-cluster"]
          namespaces: ["` + namespace + `"]
          matchLabels: {}
      egress:
        - fqdn: "` + allowedHost + `"
          ports: [443]
          tls:
            mode: passthrough
`
}

func kindHTTPSProxyStatusCode(h *kindHarness, podName string, host string, path string) string {
	return strings.TrimSpace(h.ExecPod(
		podName,
		"sh",
		"-c",
		fmt.Sprintf("curl -k -sS --proxy http://aegis:3128 -o /dev/null -w '%%{http_code}' https://%s%s", host, path),
	))
}

func kindHTTPSProxyAttempt(h *kindHarness, podName string, host string, path string) string {
	return h.ExecPod(
		podName,
		"sh",
		"-c",
		fmt.Sprintf(`set +e
output=$(curl -k -sS -v --proxy http://aegis:3128 https://%s%s -o /dev/null 2>&1)
status=$?
printf 'exit=%%d\n%%s\n' "$status" "$output"`, host, path),
	)
}

func indentYAMLBlock(value string, spaces int) string {
	prefix := strings.Repeat(" ", spaces)
	trimmed := strings.TrimSuffix(value, "\n")
	lines := strings.Split(trimmed, "\n")
	return prefix + strings.Join(lines, "\n"+prefix)
}
