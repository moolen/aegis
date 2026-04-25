//go:build kind_e2e

package e2e

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	kindImageRef     = "aegis:e2e-kind"
	kindNamespace    = "aegis-e2e"
	kindReleaseName  = "aegis"
	kindCurlPodName  = "curl"
	kindAllowedPod   = "curl-allowed"
	kindDeniedPod    = "curl-denied"
	kindEchoHostName = "echo.aegis-e2e.svc.cluster.local"
)

var (
	kindBuildOnce sync.Once
	kindBuildErr  error
)

func TestHelmChartDeploysAndEnforcesPolicyOnKind(t *testing.T) {
	repoRoot := mustRepoRoot(t)
	requireCommand(t, "docker")
	requireCommand(t, "helm")
	requireCommand(t, "kind")
	requireCommand(t, "kubectl")
	requireDockerDaemon(t)

	clusterName := fmt.Sprintf("aegis-e2e-%d", time.Now().UnixNano())
	kubeContext := "kind-" + clusterName
	createKindCluster(t, repoRoot, clusterName)
	t.Cleanup(func() {
		runBestEffort(repoRoot, 2*time.Minute, "kind", "delete", "cluster", "--name", clusterName)
	})

	ensureKindImageBuilt(t, repoRoot)
	runCommand(t, repoRoot, 5*time.Minute, "kind", "load", "docker-image", kindImageRef, "--name", clusterName)

	kubectlApplyYAML(t, repoRoot, kubeContext, kindNamespace, echoManifestYAML())
	runCommand(t, repoRoot, 3*time.Minute, "kubectl", "--context", kubeContext, "-n", kindNamespace, "rollout", "status", "deployment/echo", "--timeout=180s")

	valuesPath := writeKindValuesFile(t, kindValuesYAML())
	runCommand(
		t,
		repoRoot,
		4*time.Minute,
		"helm",
		"upgrade",
		"--install",
		kindReleaseName,
		"./deploy/helm",
		"-n",
		kindNamespace,
		"--create-namespace",
		"-f",
		valuesPath,
		"--wait",
		"--timeout",
		"180s",
	)
	runCommand(t, repoRoot, 3*time.Minute, "kubectl", "--context", kubeContext, "-n", kindNamespace, "rollout", "status", "deployment/aegis", "--timeout=180s")

	runBestEffort(repoRoot, time.Minute, "kubectl", "--context", kubeContext, "-n", kindNamespace, "delete", "pod", kindCurlPodName, "--ignore-not-found")
	runCommand(
		t,
		repoRoot,
		2*time.Minute,
		"kubectl",
		"--context",
		kubeContext,
		"-n",
		kindNamespace,
		"run",
		kindCurlPodName,
		"--restart=Never",
		"--image=curlimages/curl:8.8.0",
		"--command",
		"--",
		"sh",
		"-c",
		"sleep 3600",
	)
	runCommand(t, repoRoot, 3*time.Minute, "kubectl", "--context", kubeContext, "-n", kindNamespace, "wait", "--for=condition=Ready", "pod/"+kindCurlPodName, "--timeout=180s")

	healthz := kubectlExec(t, repoRoot, kubeContext, "curl", "-fsS", "http://aegis:9090/healthz")
	if got := strings.TrimSpace(healthz); got != "ok" {
		t.Fatalf("healthz body = %q, want %q", got, "ok")
	}
	readyz := kubectlExec(t, repoRoot, kubeContext, "curl", "-fsS", "http://aegis:9090/readyz")
	if got := strings.TrimSpace(readyz); got != "ok" {
		t.Fatalf("readyz body = %q, want %q", got, "ok")
	}

	allowedStatus := strings.TrimSpace(kubectlExec(
		t,
		repoRoot,
		kubeContext,
		"sh",
		"-c",
		fmt.Sprintf("curl -sS --proxy http://aegis:3128 -o /dev/null -w '%%{http_code}' http://%s/allowed", kindEchoHostName),
	))
	if allowedStatus != "200" {
		t.Fatalf("allowed request status = %q, want %q", allowedStatus, "200")
	}

	deniedStatus := strings.TrimSpace(kubectlExec(
		t,
		repoRoot,
		kubeContext,
		"sh",
		"-c",
		fmt.Sprintf("curl -sS --proxy http://aegis:3128 -o /dev/null -w '%%{http_code}' http://%s/denied", kindEchoHostName),
	))
	if deniedStatus != "403" {
		t.Fatalf("denied request status = %q, want %q", deniedStatus, "403")
	}

	metrics := kubectlExec(t, repoRoot, kubeContext, "curl", "-fsS", "http://aegis:9090/metrics")
	if !strings.Contains(metrics, `aegis_requests_total{method="GET",protocol="http"} 2`) {
		t.Fatalf("metrics output missing expected request counter:\n%s", metrics)
	}

	runBestEffort(repoRoot, time.Minute, "kubectl", "--context", kubeContext, "-n", kindNamespace, "delete", "pod", kindAllowedPod, "--ignore-not-found")
	runBestEffort(repoRoot, time.Minute, "kubectl", "--context", kubeContext, "-n", kindNamespace, "delete", "pod", kindDeniedPod, "--ignore-not-found")
	createCurlPod(t, repoRoot, kubeContext, kindAllowedPod, "role=allowed")
	createCurlPod(t, repoRoot, kubeContext, kindDeniedPod, "role=denied")

	identityValuesPath := writeKindValuesFile(t, kindIdentityValuesYAML())
	runCommand(
		t,
		repoRoot,
		4*time.Minute,
		"helm",
		"upgrade",
		"--install",
		kindReleaseName,
		"./deploy/helm",
		"-n",
		kindNamespace,
		"--create-namespace",
		"-f",
		identityValuesPath,
		"--wait",
		"--timeout",
		"180s",
	)
	runCommand(t, repoRoot, 3*time.Minute, "kubectl", "--context", kubeContext, "-n", kindNamespace, "rollout", "status", "deployment/aegis", "--timeout=180s")

	waitFor(t, 30*time.Second, func() bool {
		metricsBody := kubectlExecPod(t, repoRoot, kubeContext, kindAllowedPod, "curl", "-fsS", "http://aegis:9090/metrics")
		active, activeOK := metricValueOrZero(metricsBody, "aegis_discovery_providers_active", map[string]string{})
		entries, entriesOK := metricValueOrZero(metricsBody, "aegis_identity_map_entries", map[string]string{"provider": "kind-cluster", "kind": "kubernetes"})
		return activeOK && entriesOK && active == 1 && entries >= 2
	})

	identityAllowedStatus := strings.TrimSpace(kubectlExecPod(
		t,
		repoRoot,
		kubeContext,
		kindAllowedPod,
		"sh",
		"-c",
		fmt.Sprintf("curl -sS --proxy http://aegis:3128 -o /dev/null -w '%%{http_code}' http://%s/allowed", kindEchoHostName),
	))
	if identityAllowedStatus != "200" {
		t.Fatalf("identity-allowed request status = %q, want %q", identityAllowedStatus, "200")
	}

	identityDeniedStatus := strings.TrimSpace(kubectlExecPod(
		t,
		repoRoot,
		kubeContext,
		kindDeniedPod,
		"sh",
		"-c",
		fmt.Sprintf("curl -sS --proxy http://aegis:3128 -o /dev/null -w '%%{http_code}' http://%s/allowed", kindEchoHostName),
	))
	if identityDeniedStatus != "403" {
		t.Fatalf("identity-denied request status = %q, want %q", identityDeniedStatus, "403")
	}

	identityMetrics := kubectlExecPod(t, repoRoot, kubeContext, kindAllowedPod, "curl", "-fsS", "http://aegis:9090/metrics")
	if got := metricValue(t, identityMetrics, "aegis_request_decisions_total", map[string]string{
		"protocol": "http",
		"action":   "allow",
		"policy":   "allow-echo-from-allowed",
		"reason":   "policy_allowed",
	}); got != 1 {
		t.Fatalf("identity allow metric = %v, want 1", got)
	}
	if got := metricValue(t, identityMetrics, "aegis_request_decisions_total", map[string]string{
		"protocol": "http",
		"action":   "deny",
		"policy":   "none",
		"reason":   "policy_denied",
	}); got < 1 {
		t.Fatalf("identity deny metric = %v, want at least 1", got)
	}
}

func mustRepoRoot(t *testing.T) string {
	t.Helper()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd() error = %v", err)
	}

	return filepath.Dir(wd)
}

func requireCommand(t *testing.T, name string) {
	t.Helper()

	if _, err := exec.LookPath(name); err != nil {
		t.Skipf("%s not available: %v", name, err)
	}
}

func requireDockerDaemon(t *testing.T) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if output, err := exec.CommandContext(ctx, "docker", "info").CombinedOutput(); err != nil {
		t.Skipf("docker daemon unavailable: %v\n%s", err, string(output))
	}
}

func createKindCluster(t *testing.T, repoRoot string, clusterName string) {
	t.Helper()

	configPath := filepath.Join(repoRoot, "hack", "kind-config.yaml")
	var lastErr error
	for attempt := 1; attempt <= 2; attempt++ {
		_, err := runCommandOutput(
			repoRoot,
			6*time.Minute,
			"kind",
			"create",
			"cluster",
			"--name",
			clusterName,
			"--wait",
			"180s",
			"--config",
			configPath,
		)
		if err == nil {
			return
		}

		lastErr = fmt.Errorf("kind create cluster attempt %d failed: %w", attempt, err)
		runBestEffort(repoRoot, 2*time.Minute, "kind", "delete", "cluster", "--name", clusterName)
	}

	t.Fatalf("%v", lastErr)
}

func ensureKindImageBuilt(t *testing.T, repoRoot string) {
	t.Helper()

	kindBuildOnce.Do(func() {
		_, kindBuildErr = runCommandOutput(repoRoot, 10*time.Minute, "docker", "build", "-t", kindImageRef, ".")
	})

	if kindBuildErr != nil {
		t.Fatalf("ensureKindImageBuilt() error = %v", kindBuildErr)
	}
}

func kubectlApplyYAML(t *testing.T, repoRoot string, kubeContext string, namespace string, manifest string) {
	t.Helper()

	manifestPath := filepath.Join(t.TempDir(), "manifest.yaml")
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	runCommand(t, repoRoot, 2*time.Minute, "kubectl", "--context", kubeContext, "create", "namespace", namespace)
	runCommand(t, repoRoot, 2*time.Minute, "kubectl", "--context", kubeContext, "-n", namespace, "apply", "-f", manifestPath)
}

func kubectlExec(t *testing.T, repoRoot string, kubeContext string, args ...string) string {
	t.Helper()

	return kubectlExecPod(t, repoRoot, kubeContext, kindCurlPodName, args...)
}

func kubectlExecPod(t *testing.T, repoRoot string, kubeContext string, podName string, args ...string) string {
	t.Helper()

	commandArgs := []string{"--context", kubeContext, "-n", kindNamespace, "exec", podName, "--"}
	commandArgs = append(commandArgs, args...)
	return runCommand(t, repoRoot, 2*time.Minute, "kubectl", commandArgs...)
}

func writeKindValuesFile(t *testing.T, contents string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "values.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	return path
}

func runCommand(t *testing.T, dir string, timeout time.Duration, name string, args ...string) string {
	t.Helper()

	output, err := runCommandOutput(dir, timeout, name, args...)
	if err != nil {
		t.Fatalf("%s %s failed: %v\n%s", name, strings.Join(args, " "), err, output)
	}

	return output
}

func runBestEffort(dir string, timeout time.Duration, name string, args ...string) {
	_, _ = runCommandOutput(dir, timeout, name, args...)
}

func runCommandOutput(dir string, timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	output, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return string(output), fmt.Errorf("command timed out after %s", timeout)
	}
	if err != nil {
		return string(output), err
	}

	return string(output), nil
}

func createCurlPod(t *testing.T, repoRoot string, kubeContext string, podName string, labels string) {
	t.Helper()

	runCommand(
		t,
		repoRoot,
		2*time.Minute,
		"kubectl",
		"--context",
		kubeContext,
		"-n",
		kindNamespace,
		"run",
		podName,
		"--restart=Never",
		"--labels",
		labels,
		"--image=curlimages/curl:8.8.0",
		"--command",
		"--",
		"sh",
		"-c",
		"sleep 3600",
	)
	runCommand(t, repoRoot, 3*time.Minute, "kubectl", "--context", kubeContext, "-n", kindNamespace, "wait", "--for=condition=Ready", "pod/"+podName, "--timeout=180s")
}

func kindValuesYAML() string {
	return `image:
  repository: aegis
  tag: e2e-kind
  pullPolicy: IfNotPresent
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
  policies:
    - name: allow-echo
      identitySelector:
        matchLabels: {}
      egress:
        - fqdn: "echo.aegis-e2e.svc.cluster.local"
          ports: [80]
          tls:
            mode: mitm
          http:
            allowedMethods: ["GET"]
            allowedPaths: ["/allowed"]
`
}

func kindIdentityValuesYAML() string {
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
        namespaces: ["aegis-e2e"]
        resyncPeriod: 5s
  policies:
    - name: allow-echo-from-allowed
      identitySelector:
        matchLabels:
          role: "allowed"
          kubernetes.io/namespace: "aegis-e2e"
      egress:
        - fqdn: "echo.aegis-e2e.svc.cluster.local"
          ports: [80]
          tls:
            mode: mitm
          http:
            allowedMethods: ["GET"]
            allowedPaths: ["/allowed"]
`
}

func echoManifestYAML() string {
	return `apiVersion: apps/v1
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
        - name: echo
          image: hashicorp/http-echo:1.0.0
          args:
            - -listen=:5678
            - -text=ok
          ports:
            - containerPort: 5678
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
      targetPort: 5678
`
}
