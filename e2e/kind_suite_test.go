//go:build kind_e2e

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	neturl "net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestKindRunNamesAreIsolated(t *testing.T) {
	first := newKindRunNames("TestHelmChartDeploysAndEnforcesPolicyOnKind", 1)
	second := newKindRunNames("TestHelmChartDeploysAndEnforcesPolicyOnKind", 2)

	if first.namespace == second.namespace {
		t.Fatalf("namespace = %q for both runs, want unique values", first.namespace)
	}
	if first.releaseName == second.releaseName {
		t.Fatalf("releaseName = %q for both runs, want unique values", first.releaseName)
	}
	if !strings.HasPrefix(first.namespace, "aegis-e2e-") {
		t.Fatalf("namespace = %q, want aegis-e2e-* prefix", first.namespace)
	}
	if !strings.HasPrefix(first.releaseName, "aegis-") {
		t.Fatalf("releaseName = %q, want aegis-* prefix", first.releaseName)
	}
}

const (
	kindImageRef         = "aegis:e2e-kind"
	kindNamespacePrefix  = "aegis-e2e"
	kindReleasePrefix    = "aegis"
	kindSharedCluster    = "aegis-e2e-shared"
	kindAdminToken       = "kind-e2e-admin-token"
	kindCurlPodName      = "curl"
	kindAllowedPod       = "curl-allowed"
	kindDeniedPod        = "curl-denied"
	kindCurlImage        = "curlimages/curl:8.8.0"
	kindChartPath        = "./deploy/helm"
	kindDefaultTimeout   = 2 * time.Minute
	kindCommandTimeout   = 20 * time.Second
	kindDiagnosticsLimit = 50
)

var (
	kindBuildOnce sync.Once
	kindBuildErr  error

	kindSharedOnce sync.Once
	kindSharedEnv  *sharedKindEnvironment
	kindSharedErr  error

	kindHelmMu     sync.Mutex
	kindRunCounter atomic.Uint64
)

type kindRunNames struct {
	namespace   string
	releaseName string
}

type sharedKindEnvironment struct {
	repoRoot    string
	clusterName string
	kubeContext string
}

type kindHarness struct {
	t           *testing.T
	repoRoot    string
	clusterName string
	kubeContext string
	namespace   string
	releaseName string
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

func TestMain(m *testing.M) {
	code := m.Run()
	if kindSharedEnv != nil {
		runBestEffort(kindSharedEnv.repoRoot, kindDefaultTimeout, "kind", "delete", "cluster", "--name", kindSharedEnv.clusterName)
	}
	os.Exit(code)
}

func newKindHarness(t *testing.T) *kindHarness {
	t.Helper()

	repoRoot := mustRepoRoot(t)
	requireCommand(t, "docker")
	requireCommand(t, "helm")
	requireCommand(t, "kind")
	requireCommand(t, "kubectl")
	requireDockerDaemon(t)

	shared := mustSharedKindEnvironment(t, repoRoot)
	names := newKindRunNames(t.Name(), kindRunCounter.Add(1))

	h := &kindHarness{
		t:           t,
		repoRoot:    repoRoot,
		clusterName: shared.clusterName,
		kubeContext: shared.kubeContext,
		namespace:   names.namespace,
		releaseName: names.releaseName,
	}

	h.createNamespace()
	t.Cleanup(func() { h.cleanupNamespace() })
	t.Cleanup(func() {
		if t.Failed() {
			h.dumpFailureDiagnostics()
		}
	})

	return h
}

func mustSharedKindEnvironment(t *testing.T, repoRoot string) *sharedKindEnvironment {
	t.Helper()

	kindSharedOnce.Do(func() {
		clusterName := kindSharedCluster
		kubeContext := "kind-" + clusterName

		createKindCluster(t, repoRoot, clusterName)
		if kindSharedErr != nil {
			return
		}
		waitForKindControlPlaneReady(t, repoRoot, kubeContext)
		ensureKindImageBuilt(t, repoRoot)
		runCommand(t, repoRoot, 5*time.Minute, "kind", "load", "docker-image", kindImageRef, "--name", clusterName)

		kindSharedEnv = &sharedKindEnvironment{
			repoRoot:    repoRoot,
			clusterName: clusterName,
			kubeContext: kubeContext,
		}
	})

	if kindSharedErr != nil {
		t.Fatalf("shared kind environment error = %v", kindSharedErr)
	}
	if kindSharedEnv == nil {
		t.Fatal("shared kind environment not initialized")
	}

	return kindSharedEnv
}

func newKindRunNames(testName string, seq uint64) kindRunNames {
	slug := sanitizeDNSLabel(testName)
	if slug == "" {
		slug = "test"
	}
	suffix := fmt.Sprintf("%02d", seq)

	return kindRunNames{
		namespace:   buildDNSLabel(kindNamespacePrefix, slug, suffix, 63),
		releaseName: buildDNSLabel(kindReleasePrefix, slug, suffix, 53),
	}
}

func (h *kindHarness) echoHost() string {
	return fmt.Sprintf("echo.%s.svc.cluster.local", h.namespace)
}

func (h *kindHarness) createNamespace() {
	runCommand(h.t, h.repoRoot, kindDefaultTimeout, "kubectl", "--context", h.kubeContext, "create", "namespace", h.namespace)
}

func (h *kindHarness) cleanupNamespace() {
	kindHelmMu.Lock()
	defer kindHelmMu.Unlock()

	runBestEffort(h.repoRoot, kindDefaultTimeout, "helm", "uninstall", h.releaseName, "-n", h.namespace)
	runBestEffort(h.repoRoot, kindDefaultTimeout, "kubectl", "--context", h.kubeContext, "delete", "namespace", h.namespace, "--ignore-not-found", "--wait=false")
	if waitForNamespaceDeleted(h.repoRoot, h.kubeContext, h.namespace, 45*time.Second) {
		return
	}

	runBestEffort(
		h.repoRoot,
		kindDefaultTimeout,
		"kubectl",
		"--context",
		h.kubeContext,
		"patch",
		"namespace",
		h.namespace,
		"--type=merge",
		"-p",
		`{"metadata":{"finalizers":[]}}`,
	)
	_ = waitForNamespaceDeleted(h.repoRoot, h.kubeContext, h.namespace, 15*time.Second)
}

func (h *kindHarness) HelmUpgradeInstall(valuesYAML string) {
	h.t.Helper()

	valuesPath := writeKindValuesFile(h.t, valuesYAML)

	kindHelmMu.Lock()
	defer kindHelmMu.Unlock()

	var lastErr error
	for attempt := 1; attempt <= 2; attempt++ {
		output, err := runCommandOutput(
			h.repoRoot,
			4*time.Minute,
			"helm",
			"upgrade",
			"--install",
			"--reset-values",
			h.releaseName,
			kindChartPath,
			"-n",
			h.namespace,
			"--create-namespace",
			"-f",
			valuesPath,
			"--wait",
			"--timeout",
			"180s",
		)
		if err == nil {
			return
		}
		lastErr = fmt.Errorf("helm upgrade/install attempt %d failed: %w\n%s", attempt, err, output)
		runBestEffort(h.repoRoot, kindDefaultTimeout, "helm", "uninstall", h.releaseName, "-n", h.namespace)
		time.Sleep(2 * time.Second)
	}

	h.t.Fatal(lastErr)
}

func (h *kindHarness) RolloutRestartDeployment(name string) {
	runCommand(h.t, h.repoRoot, kindDefaultTimeout, "kubectl", "--context", h.kubeContext, "-n", h.namespace, "rollout", "restart", "deployment/"+name)
}

func (h *kindHarness) WaitForDeploymentAvailable(name string, timeout time.Duration) {
	waitForDeploymentAvailable(h.t, h.repoRoot, h.kubeContext, h.namespace, name, timeout)
}

func (h *kindHarness) ApplyYAML(manifest string) {
	kubectlApplyYAML(h.t, h.repoRoot, h.kubeContext, h.namespace, manifest)
}

func (h *kindHarness) DeletePodIfPresent(name string) {
	runBestEffort(h.repoRoot, time.Minute, "kubectl", "--context", h.kubeContext, "-n", h.namespace, "delete", "pod", name, "--ignore-not-found")
}

func (h *kindHarness) RunDefaultCurlPod() {
	h.DeletePodIfPresent(kindCurlPodName)
	runCommand(
		h.t,
		h.repoRoot,
		kindDefaultTimeout,
		"kubectl",
		"--context",
		h.kubeContext,
		"-n",
		h.namespace,
		"run",
		kindCurlPodName,
		"--restart=Never",
		"--image="+kindCurlImage,
		"--command",
		"--",
		"sh",
		"-c",
		"sleep 3600",
	)
	runCommand(h.t, h.repoRoot, 3*time.Minute, "kubectl", "--context", h.kubeContext, "-n", h.namespace, "wait", "--for=condition=Ready", "pod/"+kindCurlPodName, "--timeout=180s")
}

func (h *kindHarness) CreateCurlPod(name string, labels string) {
	createCurlPod(h.t, h.repoRoot, h.kubeContext, h.namespace, name, labels)
}

func (h *kindHarness) Exec(args ...string) string {
	return h.ExecPod(kindCurlPodName, args...)
}

func (h *kindHarness) ExecPod(podName string, args ...string) string {
	return kubectlExecPod(h.t, h.repoRoot, h.kubeContext, h.namespace, podName, args...)
}

func (h *kindHarness) ExecPodEventually(timeout time.Duration, podName string, args ...string) string {
	return kubectlExecPodEventually(h.t, h.repoRoot, timeout, h.kubeContext, h.namespace, podName, args...)
}

func (h *kindHarness) PodIP(podName string) string {
	return kindPodIP(h.t, h.repoRoot, h.kubeContext, h.namespace, podName)
}

func (h *kindHarness) ProxyStatusCode(podName string, path string) string {
	return strings.TrimSpace(h.ExecPod(
		podName,
		"sh",
		"-c",
		fmt.Sprintf("curl -sS --proxy http://aegis:3128 -o /dev/null -w '%%{http_code}' http://%s%s", h.echoHost(), path),
	))
}

func (h *kindHarness) Metrics(podName string) string {
	return h.ExecPod(podName, "curl", "-fsS", "http://aegis:9090/metrics")
}

func (h *kindHarness) AdminSimulateEventually(podName string, timeout time.Duration, sourceIP string, fqdn string, port int, protocol string, method string, path string) string {
	query := neturl.Values{}
	query.Set("sourceIP", sourceIP)
	query.Set("fqdn", fqdn)
	query.Set("port", fmt.Sprintf("%d", port))
	query.Set("protocol", protocol)
	query.Set("method", method)
	query.Set("path", path)

	adminURL := neturl.URL{
		Scheme:   "http",
		Host:     "aegis:9090",
		Path:     "/admin/simulate",
		RawQuery: query.Encode(),
	}

	return h.ExecPodEventually(
		timeout,
		podName,
		"sh",
		"-c",
		fmt.Sprintf("curl -fsS --max-time 10 -H 'Authorization: Bearer %s' '%s'", kindAdminToken, adminURL.String()),
	)
}

func (h *kindHarness) dumpFailureDiagnostics() {
	h.t.Helper()

	commands := []struct {
		label string
		args  []string
	}{
		{
			label: "namespace resources",
			args:  []string{"--context", h.kubeContext, "-n", h.namespace, "get", "all,configmap,secret", "-o", "wide"},
		},
		{
			label: "namespace events",
			args:  []string{"--context", h.kubeContext, "-n", h.namespace, "get", "events", "--sort-by=.lastTimestamp"},
		},
		{
			label: "aegis deployment",
			args:  []string{"--context", h.kubeContext, "-n", h.namespace, "describe", "deployment", "aegis"},
		},
		{
			label: "aegis logs",
			args:  []string{"--context", h.kubeContext, "-n", h.namespace, "logs", "deployment/aegis", "--all-containers", "--tail", fmt.Sprintf("%d", kindDiagnosticsLimit)},
		},
	}

	for _, command := range commands {
		output, err := runCommandOutput(h.repoRoot, kindDefaultTimeout, "kubectl", command.args...)
		if err != nil {
			h.t.Logf("%s failed: %v\n%s", command.label, err, output)
			continue
		}
		h.t.Logf("%s:\n%s", command.label, output)
	}
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
	cleanupKindClusterArtifacts(repoRoot, clusterName)
	var lastErr error
	for attempt := 1; attempt <= 2; attempt++ {
		output, err := runCommandOutput(
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

		lastErr = fmt.Errorf("kind create cluster attempt %d failed: %w\n%s", attempt, err, output)
		cleanupKindClusterArtifacts(repoRoot, clusterName)
	}

	kindSharedErr = lastErr
}

func cleanupKindClusterArtifacts(repoRoot string, clusterName string) {
	runBestEffort(repoRoot, kindDefaultTimeout, "kind", "delete", "cluster", "--name", clusterName)
	runBestEffort(repoRoot, kindDefaultTimeout, "docker", "rm", "-f", clusterName+"-control-plane")
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

func waitForKindControlPlaneReady(t *testing.T, repoRoot string, kubeContext string) {
	t.Helper()

	waitFor(t, kindDefaultTimeout, func() bool {
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

func kubectlExecPodEventually(t *testing.T, repoRoot string, timeout time.Duration, kubeContext string, namespace string, podName string, args ...string) string {
	t.Helper()

	deadline := time.Now().Add(timeout)
	var lastOutput string
	var lastErr error
	for time.Now().Before(deadline) {
		output, err := tryKubectlExecPod(repoRoot, kubeContext, namespace, podName, args...)
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

func kubectlExecPod(t *testing.T, repoRoot string, kubeContext string, namespace string, podName string, args ...string) string {
	t.Helper()

	return kubectlExecPodEventually(t, repoRoot, 30*time.Second, kubeContext, namespace, podName, args...)
}

func tryKubectlExecPod(repoRoot string, kubeContext string, namespace string, podName string, args ...string) (string, error) {
	commandArgs := []string{"--context", kubeContext, "-n", namespace, "exec", podName, "--"}
	commandArgs = append(commandArgs, args...)
	return runCommandOutput(repoRoot, kindCommandTimeout, "kubectl", commandArgs...)
}

func kindPodIP(t *testing.T, repoRoot string, kubeContext string, namespace string, podName string) string {
	t.Helper()

	return strings.TrimSpace(runCommand(
		t,
		repoRoot,
		kindDefaultTimeout,
		"kubectl",
		"--context",
		kubeContext,
		"-n",
		namespace,
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

func waitForNamespaceDeleted(repoRoot string, kubeContext string, namespace string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		_, err := runCommandOutput(repoRoot, 10*time.Second, "kubectl", "--context", kubeContext, "get", "namespace", namespace)
		if err != nil {
			return true
		}
		time.Sleep(time.Second)
	}
	return false
}

func createCurlPod(t *testing.T, repoRoot string, kubeContext string, namespace string, podName string, labels string) {
	t.Helper()

	runCommand(
		t,
		repoRoot,
		kindDefaultTimeout,
		"kubectl",
		"--context",
		kubeContext,
		"-n",
		namespace,
		"run",
		podName,
		"--restart=Never",
		"--labels",
		labels,
		"--image="+kindCurlImage,
		"--command",
		"--",
		"sh",
		"-c",
		"sleep 3600",
	)
	runCommand(t, repoRoot, 3*time.Minute, "kubectl", "--context", kubeContext, "-n", namespace, "wait", "--for=condition=Ready", "pod/"+podName, "--timeout=180s")
}

func kindValuesYAML(namespace string, cidr string) string {
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
    - name: allow-echo-from-cidr
      subjects:
        cidrs: ["` + cidr + `"]
      egress:
        - fqdn: "echo.` + namespace + `.svc.cluster.local"
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

func kindIdentityValuesYAML(namespace string) string {
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
