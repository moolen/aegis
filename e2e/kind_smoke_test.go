//go:build kind_e2e

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
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
	kindAdminToken   = "kind-e2e-admin-token"
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
	waitForKindControlPlaneReady(t, repoRoot, kubeContext)
	t.Cleanup(func() {
		runBestEffort(repoRoot, 2*time.Minute, "kind", "delete", "cluster", "--name", clusterName)
	})

	ensureKindImageBuilt(t, repoRoot)
	runCommand(t, repoRoot, 5*time.Minute, "kind", "load", "docker-image", kindImageRef, "--name", clusterName)

	kubectlApplyYAML(t, repoRoot, kubeContext, kindNamespace, echoManifestYAML())
	waitForDeploymentAvailable(t, repoRoot, kubeContext, kindNamespace, "echo", 3*time.Minute)

	runBestEffort(repoRoot, time.Minute, "kubectl", "--context", kubeContext, "-n", kindNamespace, "delete", "pod", kindCurlPodName, "--ignore-not-found")
	runBestEffort(repoRoot, time.Minute, "kubectl", "--context", kubeContext, "-n", kindNamespace, "delete", "pod", kindAllowedPod, "--ignore-not-found")
	runBestEffort(repoRoot, time.Minute, "kubectl", "--context", kubeContext, "-n", kindNamespace, "delete", "pod", kindDeniedPod, "--ignore-not-found")
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
	createCurlPod(t, repoRoot, kubeContext, kindAllowedPod, "role=allowed")
	createCurlPod(t, repoRoot, kubeContext, kindDeniedPod, "role=denied")

	allowedPodIP := kindPodIP(t, repoRoot, kubeContext, kindAllowedPod)
	deniedPodIP := kindPodIP(t, repoRoot, kubeContext, kindDeniedPod)

	valuesPath := writeKindValuesFile(t, kindValuesYAML(kindHostCIDR(t, allowedPodIP)))
	runCommand(
		t,
		repoRoot,
		4*time.Minute,
		"helm",
		"upgrade",
		"--install",
		"--reset-values",
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
	runCommand(t, repoRoot, 2*time.Minute, "kubectl", "--context", kubeContext, "-n", kindNamespace, "rollout", "restart", "deployment/aegis")
	waitForDeploymentAvailable(t, repoRoot, kubeContext, kindNamespace, "aegis", 3*time.Minute)

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

	cidrAllowedSimulationURL := fmt.Sprintf("http://aegis:9090/admin/simulate?sourceIP=%s&fqdn=%s&port=80&protocol=http&method=GET&path=/cidr", allowedPodIP, kindEchoHostName)
	cidrDeniedSimulationURL := fmt.Sprintf("http://aegis:9090/admin/simulate?sourceIP=%s&fqdn=%s&port=80&protocol=http&method=GET&path=/cidr", deniedPodIP, kindEchoHostName)
	cidrAllowedSimulation := kubectlExecPodEventually(
		t,
		repoRoot,
		30*time.Second,
		kubeContext,
		kindAllowedPod,
		"sh",
		"-c",
		fmt.Sprintf("curl -fsS --max-time 10 -H 'Authorization: Bearer %s' '%s'", kindAdminToken, cidrAllowedSimulationURL),
	)
	if !strings.Contains(cidrAllowedSimulation, `"action":"allow"`) || !strings.Contains(cidrAllowedSimulation, `"policy":"allow-echo-from-cidr"`) {
		t.Fatalf("cidr allowed simulation = %s, want allow-echo-from-cidr allow", cidrAllowedSimulation)
	}

	cidrDeniedSimulation := kubectlExecPodEventually(
		t,
		repoRoot,
		30*time.Second,
		kubeContext,
		kindAllowedPod,
		"sh",
		"-c",
		fmt.Sprintf("curl -fsS --max-time 10 -H 'Authorization: Bearer %s' '%s'", kindAdminToken, cidrDeniedSimulationURL),
	)
	if !strings.Contains(cidrDeniedSimulation, `"action":"deny"`) || !strings.Contains(cidrDeniedSimulation, `"reason":"policy_denied"`) {
		t.Fatalf("cidr denied simulation = %s, want deny policy_denied", cidrDeniedSimulation)
	}

	cidrAllowedStatus := strings.TrimSpace(kubectlExecPod(
		t,
		repoRoot,
		kubeContext,
		kindAllowedPod,
		"sh",
		"-c",
		fmt.Sprintf("curl -sS --proxy http://aegis:3128 -o /dev/null -w '%%{http_code}' http://%s/cidr", kindEchoHostName),
	))
	if cidrAllowedStatus != "200" {
		t.Fatalf("cidr-allowed request status = %q, want %q", cidrAllowedStatus, "200")
	}

	cidrDeniedStatus := strings.TrimSpace(kubectlExecPod(
		t,
		repoRoot,
		kubeContext,
		kindDeniedPod,
		"sh",
		"-c",
		fmt.Sprintf("curl -sS --proxy http://aegis:3128 -o /dev/null -w '%%{http_code}' http://%s/cidr", kindEchoHostName),
	))
	if cidrDeniedStatus != "403" {
		t.Fatalf("cidr-denied request status = %q, want %q", cidrDeniedStatus, "403")
	}

	identityValuesPath := writeKindValuesFile(t, kindIdentityValuesYAML())
	runCommand(
		t,
		repoRoot,
		4*time.Minute,
		"helm",
		"upgrade",
		"--install",
		"--reset-values",
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
	runCommand(t, repoRoot, 2*time.Minute, "kubectl", "--context", kubeContext, "-n", kindNamespace, "rollout", "restart", "deployment/aegis")
	waitForDeploymentAvailable(t, repoRoot, kubeContext, kindNamespace, "aegis", 3*time.Minute)

	waitFor(t, 30*time.Second, func() bool {
		metricsBody, err := tryKubectlExecPod(repoRoot, kubeContext, kindAllowedPod, "curl", "-fsS", "http://aegis:9090/metrics")
		if err != nil {
			return false
		}
		active, activeOK := metricValueOrZero(metricsBody, "aegis_discovery_providers_active", map[string]string{})
		entries, entriesOK := metricValueOrZero(metricsBody, "aegis_identity_map_entries", map[string]string{"provider": "kind-cluster", "kind": "kubernetes"})
		return activeOK && entriesOK && active == 1 && entries >= 2
	})

	allowedSimulationURL := fmt.Sprintf("http://aegis:9090/admin/simulate?sourceIP=%s&fqdn=%s&port=80&protocol=http&method=GET&path=/allowed", allowedPodIP, kindEchoHostName)
	deniedSimulationURL := fmt.Sprintf("http://aegis:9090/admin/simulate?sourceIP=%s&fqdn=%s&port=80&protocol=http&method=GET&path=/allowed", deniedPodIP, kindEchoHostName)

	allowedSimulation := kubectlExecPodEventually(
		t,
		repoRoot,
		30*time.Second,
		kubeContext,
		kindAllowedPod,
		"sh",
		"-c",
		fmt.Sprintf("curl -fsS --max-time 10 -H 'Authorization: Bearer %s' '%s'", kindAdminToken, allowedSimulationURL),
	)
	if !strings.Contains(allowedSimulation, `"action":"allow"`) || !strings.Contains(allowedSimulation, `"policy":"allow-echo-from-allowed"`) {
		t.Fatalf("allowed simulation = %s, want allow-echo-from-allowed allow", allowedSimulation)
	}

	deniedSimulation := kubectlExecPodEventually(
		t,
		repoRoot,
		30*time.Second,
		kubeContext,
		kindAllowedPod,
		"sh",
		"-c",
		fmt.Sprintf("curl -fsS --max-time 10 -H 'Authorization: Bearer %s' '%s'", kindAdminToken, deniedSimulationURL),
	)
	if !strings.Contains(deniedSimulation, `"action":"deny"`) || !strings.Contains(deniedSimulation, `"reason":"policy_denied"`) {
		t.Fatalf("denied simulation = %s, want deny policy_denied", deniedSimulation)
	}

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

	identityMetrics := kubectlExecPod(t, repoRoot, kubeContext, kindAllowedPod, "curl", "-fsS", "http://aegis:9090/metrics")
	if got := metricValue(t, identityMetrics, "aegis_request_decisions_total", map[string]string{
		"protocol": "http",
		"action":   "allow",
		"policy":   "allow-echo-from-allowed",
		"reason":   "policy_allowed",
	}); got != 1 {
		t.Fatalf("identity allow metric = %v, want 1", got)
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

type podList struct {
	Items []struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
		Status struct {
			Conditions []statusCondition `json:"conditions"`
		} `json:"status"`
	} `json:"items"`
}

type deploymentStatus struct {
	Metadata struct {
		Generation int64 `json:"generation"`
	} `json:"metadata"`
	Spec struct {
		Replicas *int32 `json:"replicas"`
	} `json:"spec"`
	Status struct {
		ObservedGeneration  int64             `json:"observedGeneration"`
		Replicas            int32             `json:"replicas"`
		UpdatedReplicas     int32             `json:"updatedReplicas"`
		ReadyReplicas       int32             `json:"readyReplicas"`
		AvailableReplicas   int32             `json:"availableReplicas"`
		UnavailableReplicas int32             `json:"unavailableReplicas"`
		Conditions          []statusCondition `json:"conditions"`
	} `json:"status"`
}

type statusCondition struct {
	Type   string `json:"type"`
	Status string `json:"status"`
}

func waitForKindControlPlaneReady(t *testing.T, repoRoot string, kubeContext string) {
	t.Helper()

	waitFor(t, 2*time.Minute, func() bool {
		output, err := runCommandOutput(repoRoot, 15*time.Second, "kubectl", "--context", kubeContext, "-n", "kube-system", "get", "pods", "-o", "json")
		if err != nil {
			return false
		}

		var pods podList
		if err := json.Unmarshal([]byte(output), &pods); err != nil {
			return false
		}

		schedulerReady := false
		controllerReady := false
		for _, pod := range pods.Items {
			if strings.HasPrefix(pod.Metadata.Name, "kube-scheduler-") && podReady(pod.Status.Conditions) {
				schedulerReady = true
			}
			if strings.HasPrefix(pod.Metadata.Name, "kube-controller-manager-") && podReady(pod.Status.Conditions) {
				controllerReady = true
			}
		}

		return schedulerReady && controllerReady
	})
}

func waitForDeploymentAvailable(t *testing.T, repoRoot string, kubeContext string, namespace string, name string, timeout time.Duration) {
	t.Helper()

	waitFor(t, timeout, func() bool {
		output, err := runCommandOutput(repoRoot, 15*time.Second, "kubectl", "--context", kubeContext, "-n", namespace, "get", "deployment", name, "-o", "json")
		if err != nil {
			return false
		}

		var status deploymentStatus
		if err := json.Unmarshal([]byte(output), &status); err != nil {
			return false
		}

		replicas := int32(1)
		if status.Spec.Replicas != nil {
			replicas = *status.Spec.Replicas
		}

		return status.Status.ObservedGeneration >= status.Metadata.Generation &&
			status.Status.UpdatedReplicas == replicas &&
			status.Status.ReadyReplicas == replicas &&
			status.Status.AvailableReplicas == replicas &&
			status.Status.UnavailableReplicas == 0 &&
			conditionTrue(status.Status.Conditions, "Available")
	})
}

func podReady(conditions []statusCondition) bool {
	return conditionTrue(conditions, "Ready")
}

func conditionTrue(conditions []statusCondition, wantType string) bool {
	for _, condition := range conditions {
		if condition.Type == wantType && condition.Status == "True" {
			return true
		}
	}
	return false
}

func kubectlExecPodEventually(t *testing.T, repoRoot string, timeout time.Duration, kubeContext string, podName string, args ...string) string {
	t.Helper()

	deadline := time.Now().Add(timeout)
	var lastOutput string
	var lastErr error
	for time.Now().Before(deadline) {
		output, err := tryKubectlExecPod(repoRoot, kubeContext, podName, args...)
		if err == nil {
			return output
		}
		lastOutput = output
		lastErr = err
		time.Sleep(250 * time.Millisecond)
	}

	t.Fatalf("kubectl exec %s did not succeed before timeout: %v\n%s", podName, lastErr, lastOutput)
	return ""
}

func kubectlExecPod(t *testing.T, repoRoot string, kubeContext string, podName string, args ...string) string {
	t.Helper()

	return kubectlExecPodEventually(t, repoRoot, 30*time.Second, kubeContext, podName, args...)
}

func tryKubectlExecPod(repoRoot string, kubeContext string, podName string, args ...string) (string, error) {
	commandArgs := []string{"--context", kubeContext, "-n", kindNamespace, "exec", podName, "--"}
	commandArgs = append(commandArgs, args...)
	return runCommandOutput(repoRoot, 20*time.Second, "kubectl", commandArgs...)
}

func kindPodIP(t *testing.T, repoRoot string, kubeContext string, podName string) string {
	t.Helper()

	return strings.TrimSpace(runCommand(
		t,
		repoRoot,
		2*time.Minute,
		"kubectl",
		"--context",
		kubeContext,
		"-n",
		kindNamespace,
		"get",
		"pod",
		podName,
		"-o",
		"jsonpath={.status.podIP}",
	))
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

func kindValuesYAML(cidr string) string {
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
        namespaces: ["aegis-e2e"]
        resyncPeriod: 5s
  policies:
    - name: allow-echo-from-cidr
      subjects:
        cidrs: ["` + cidr + `"]
      egress:
        - fqdn: "echo.aegis-e2e.svc.cluster.local"
          ports: [80]
          tls:
            mode: mitm
          http:
            allowedMethods: ["GET"]
            allowedPaths: ["/cidr"]
    - name: allow-echo
      subjects:
        kubernetes:
          discoveryNames: ["kind-cluster"]
          namespaces: ["aegis-e2e"]
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
        namespaces: ["aegis-e2e"]
        resyncPeriod: 5s
  policies:
    - name: allow-echo-from-allowed
      subjects:
        kubernetes:
          discoveryNames: ["kind-cluster"]
          namespaces: ["aegis-e2e"]
          matchLabels:
            role: "allowed"
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

func kindHostCIDR(t *testing.T, ip string) string {
	t.Helper()

	addr, err := netip.ParseAddr(ip)
	if err != nil {
		t.Fatalf("ParseAddr(%q) error = %v", ip, err)
	}
	addr = addr.Unmap()
	return netip.PrefixFrom(addr, addr.BitLen()).String()
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
