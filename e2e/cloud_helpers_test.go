//go:build cloud_e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/bloberror"
)

const (
	cloudCommandTimeout      = 30 * time.Second
	cloudNamespaceWait       = 45 * time.Second
	cloudNamespaceFinalizers = 15 * time.Second
)

type cloudHarness struct {
	t                *testing.T
	cfg              cloudConfig
	repoRoot         string
	kubeContext      string
	namespace        string
	prefix           string
	cleanupPolicies  bool
	baselinePolicies float64
	baselineSet      bool
}

func newCloudHarness(t *testing.T) *cloudHarness {
	t.Helper()

	cfg := mustCloudConfig(t)
	names := newCloudRunNames(t.Name(), cloudRunCounter.Add(1))

	h := &cloudHarness{
		t:               t,
		cfg:             cfg,
		repoRoot:        mustRepoRoot(t),
		kubeContext:     currentCloudKubeContext(t),
		namespace:       names.namespace,
		prefix:          names.prefix,
		cleanupPolicies: true,
	}
	h.createNamespace(t)
	h.baselinePolicies = h.waitForConsistentRemotePolicyCount(t)
	h.baselineSet = true

	t.Cleanup(func() {
		if !cfg.keepArtifacts {
			h.cleanup()
		}
	})
	t.Cleanup(func() {
		if t.Failed() {
			h.dumpFailureDiagnostics()
		}
	})

	return h
}

func (h *cloudHarness) cleanup() {
	if h.cleanupPolicies {
		for _, object := range h.listPolicyObjects(h.t) {
			_, _ = h.blobClient(h.t).DeleteBlob(context.Background(), h.cfg.policyContainer, object, nil)
		}
	}
	h.deleteNamespace(h.t)
}

func (h *cloudHarness) dumpFailureDiagnostics() {
	h.t.Helper()

	for _, command := range []struct {
		label string
		args  []string
	}{
		{
			label: "namespace resources",
			args:  h.kubectlNamespaceArgs("get", "all,configmap,secret", "-o", "wide"),
		},
		{
			label: "namespace events",
			args:  h.kubectlNamespaceArgs("get", "events", "--sort-by=.lastTimestamp"),
		},
	} {
		output, err := runCloudCommandOutput(cloudCommandTimeout, "kubectl", command.args...)
		if err != nil {
			h.t.Logf("%s failed: %v\n%s", command.label, err, output)
			continue
		}
		h.t.Logf("%s:\n%s", command.label, output)
	}
}

func (h *cloudHarness) objectPrefix(parts ...string) string {
	segments := []string{strings.Trim(h.prefix, "/")}
	for _, part := range parts {
		if trimmed := strings.Trim(part, "/"); trimmed != "" {
			segments = append(segments, trimmed)
		}
	}
	return strings.Join(segments, "/")
}

func (h *cloudHarness) waitFor(timeout time.Duration, cond func() bool) {
	h.t.Helper()

	if timeout <= 0 {
		timeout = h.cfg.timeout
	}
	waitFor(h.t, timeout, cond)
}

func (h *cloudHarness) policyObjectKey(name string) string {
	return h.objectPrefix(name)
}

func (h *cloudHarness) putPolicyObject(t *testing.T, name string, body []byte) {
	t.Helper()

	_, err := h.blobClient(t).UploadBuffer(
		context.Background(),
		h.cfg.policyContainer,
		h.storageObjectKey(name),
		body,
		nil,
	)
	if err != nil {
		t.Fatalf("upload policy object %q: %v", name, err)
	}
}

func (h *cloudHarness) deletePolicyObject(t *testing.T, name string) {
	t.Helper()

	_, err := h.blobClient(t).DeleteBlob(
		context.Background(),
		h.cfg.policyContainer,
		h.storageObjectKey(name),
		nil,
	)
	if err != nil && !bloberror.HasCode(err, bloberror.BlobNotFound) {
		t.Fatalf("delete policy object %q: %v", name, err)
	}
}

func (h *cloudHarness) listPolicyObjects(t *testing.T) []string {
	t.Helper()

	prefix := h.storagePrefix()
	pager := h.blobClient(t).NewListBlobsFlatPager(h.cfg.policyContainer, &azblob.ListBlobsFlatOptions{
		Prefix: &prefix,
	})

	var objects []string
	for pager.More() {
		page, err := pager.NextPage(context.Background())
		if err != nil {
			t.Fatalf("list policy objects under %q: %v", prefix, err)
		}
		for _, item := range page.Segment.BlobItems {
			if item == nil || item.Name == nil {
				continue
			}
			objects = append(objects, *item.Name)
		}
	}
	sort.Strings(objects)
	return objects
}

func (h *cloudHarness) createNamespace(t *testing.T) {
	t.Helper()

	runCloudCommand(t, cloudDefaultTimeout, "kubectl", h.kubectlArgs("create", "namespace", h.namespace)...)
}

func (h *cloudHarness) deleteNamespace(t *testing.T) {
	t.Helper()

	_, _ = runCloudCommandOutput(cloudCommandTimeout, "kubectl", h.kubectlArgs("delete", "namespace", h.namespace, "--ignore-not-found", "--wait=false")...)
	if waitForCloudNamespaceDeleted(h.kubeContext, h.namespace, cloudNamespaceWait) {
		return
	}

	_, _ = runCloudCommandOutput(
		cloudCommandTimeout,
		"kubectl",
		h.kubectlArgs(
			"patch",
			"namespace",
			h.namespace,
			"--type=merge",
			"-p",
			`{"metadata":{"finalizers":[]}}`,
		)...,
	)
	_ = waitForCloudNamespaceDeleted(h.kubeContext, h.namespace, cloudNamespaceFinalizers)
}

func (h *cloudHarness) scaleDeployment(t *testing.T, name string, replicas int32) {
	t.Helper()

	runCloudCommand(
		t,
		cloudDefaultTimeout,
		"kubectl",
		h.kubectlNamespaceArgs("scale", "deployment/"+name, "--replicas", fmt.Sprintf("%d", replicas))...,
	)
	waitForDeploymentAvailable(t, h.repoRoot, h.kubeContext, h.namespace, name, cloudDefaultTimeout)
}

func (h *cloudHarness) execPod(t *testing.T, podName string, args ...string) string {
	t.Helper()

	return h.execTarget(t, podName, args...)
}

func (h *cloudHarness) execProbe(t *testing.T, args ...string) string {
	t.Helper()

	target := firstNonEmpty(os.Getenv("CLOUD_E2E_PROBE_TARGET"), "deploy/sample-client")
	return h.execTarget(t, target, args...)
}

func (h *cloudHarness) execMetricsProbe(t *testing.T, args ...string) string {
	t.Helper()

	commandArgs := cloudKubectlArgs(h.kubeContext, "-n", h.cfg.probeNamespace, "exec", h.cfg.probeTarget, "--")
	commandArgs = append(commandArgs, args...)
	return runCloudCommand(t, cloudCommandTimeout, "kubectl", commandArgs...)
}

func (h *cloudHarness) metricsBody(t *testing.T, endpoint string) string {
	t.Helper()

	return h.execMetricsProbe(t, "curl", "-fsS", fmt.Sprintf("http://%s/metrics", endpoint))
}

func (h *cloudHarness) blobClient(t *testing.T) *azblob.Client {
	t.Helper()

	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		t.Fatalf("create Azure default credential: %v", err)
	}

	client, err := azblob.NewClient(
		fmt.Sprintf("https://%s.blob.core.windows.net/", h.cfg.storageAccount),
		cred,
		nil,
	)
	if err != nil {
		t.Fatalf("create Azure blob client: %v", err)
	}
	return client
}

func (h *cloudHarness) storageObjectKey(name string) string {
	return joinCloudObjectPath(h.cfg.policyPrefix, h.policyObjectKey(name))
}

func (h *cloudHarness) storagePrefix() string {
	return joinCloudObjectPath(h.cfg.policyPrefix, strings.Trim(h.prefix, "/"))
}

func (h *cloudHarness) execTarget(t *testing.T, target string, args ...string) string {
	t.Helper()

	commandArgs := append(h.kubectlNamespaceArgs("exec", target, "--"), args...)
	return runCloudCommand(t, cloudCommandTimeout, "kubectl", commandArgs...)
}

func (h *cloudHarness) newSiblingNamespace(t *testing.T) *cloudHarness {
	t.Helper()

	names := newCloudRunNames(t.Name()+"Sibling", cloudRunCounter.Add(1))
	sibling := &cloudHarness{
		t:                t,
		cfg:              h.cfg,
		repoRoot:         h.repoRoot,
		kubeContext:      h.kubeContext,
		namespace:        names.namespace,
		prefix:           h.prefix,
		cleanupPolicies:  false,
		baselinePolicies: h.baselinePolicies,
		baselineSet:      h.baselineSet,
	}
	sibling.createNamespace(t)
	t.Cleanup(func() {
		if !h.cfg.keepArtifacts {
			sibling.cleanup()
		}
	})
	return sibling
}

func (h *cloudHarness) ensureClientWorkload(t *testing.T, labels map[string]string) {
	t.Helper()

	if labels == nil {
		labels = map[string]string{}
	}
	if _, ok := labels["app"]; !ok {
		labels["app"] = "sample-client"
	}

	kubectlApplyYAML(t, h.repoRoot, h.kubeContext, h.namespace, h.clientWorkloadYAML(labels))
	waitForDeploymentAvailable(t, h.repoRoot, h.kubeContext, h.namespace, "sample-client", cloudDefaultTimeout)
}

func (h *cloudHarness) putPolicyFixture(t *testing.T, name string, body string) {
	t.Helper()

	h.putPolicyObject(t, name, []byte(body))
}

func (h *cloudHarness) deletePolicyFixture(t *testing.T, name string) {
	t.Helper()

	h.deletePolicyObject(t, name)
}

type cloudPolicyOption func(*cloudPolicyFixture)

type cloudPolicyFixture struct {
	allowedPaths []string
}

func withAllowedPaths(paths ...string) cloudPolicyOption {
	return func(cfg *cloudPolicyFixture) {
		cfg.allowedPaths = append([]string(nil), paths...)
	}
}

func (h *cloudHarness) allowHTTPPolicyYAML(appLabel string, namespaces []string, opts ...cloudPolicyOption) string {
	cfg := cloudPolicyFixture{
		allowedPaths: []string{"/static/allowed"},
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	policyName := buildDNSLabel("allow-http", sanitizeDNSLabel(h.prefix), "", 63)

	return fmt.Sprintf(`apiVersion: aegis.io/v1alpha1
kind: ProxyPolicy
metadata:
  name: %s
spec:
  subjects:
    kubernetes:
      discoveryNames: ["aks-cloud"]
      namespaces: [%s]
      matchLabels:
        app: %s
  egress:
    - fqdn: "nginx.aegis.internal"
      ports: [80]
      tls:
        mode: mitm
      http:
        allowedMethods: ["GET"]
        allowedPaths: [%s]
`,
		quoteYAML(policyName),
		joinQuotedYAML(namespaces),
		quoteYAML(appLabel),
		joinQuotedYAML(cfg.allowedPaths),
	)
}

func (h *cloudHarness) requireHTTPAllowed(t *testing.T, path string) {
	t.Helper()
	h.requireHTTPStatus(t, path, "200")
}

func (h *cloudHarness) requireHTTPDenied(t *testing.T, path string) {
	t.Helper()
	h.requireHTTPStatus(t, path, "403")
}

func (h *cloudHarness) requireHTTPStatus(t *testing.T, path string, wantStatus string) {
	t.Helper()

	h.waitFor(0, func() bool {
		wantPolicies := h.expectedPolicyCount(t)
		for _, endpoint := range h.cfg.metricsEndpoints {
			if got := h.proxyStatusCodeForProxy(t, h.proxyURLForMetricsEndpoint(t, endpoint), path); got != wantStatus {
				return false
			}
			metrics := h.metricsBody(t, endpoint)
			got, ok := metricValueOrZero(metrics, "aegis_policy_discovery_policies_active", map[string]string{
				"provider": "azure",
				"source":   "azure-policies",
			})
			if !ok || got != wantPolicies {
				return false
			}
		}
		return true
	})
}

func (h *cloudHarness) proxyStatusCode(t *testing.T, path string) string {
	t.Helper()

	return h.proxyStatusCodeForProxy(t, h.cfg.proxyURL, path)
}

func (h *cloudHarness) proxyStatusCodeForProxy(t *testing.T, proxyURL string, path string) string {
	t.Helper()

	target := h.targetURLForPath(t, path)
	command := fmt.Sprintf(
		"curl -sS --proxy %s -o /dev/null -w '%%{http_code}' %s",
		shellQuote(proxyURL),
		shellQuote(target),
	)
	return strings.TrimSpace(h.execProbe(t, "sh", "-c", command))
}

func (h *cloudHarness) scaleClientDeployment(t *testing.T, replicas int32) {
	t.Helper()
	h.scaleDeployment(t, "sample-client", replicas)
}

func (h *cloudHarness) restartClientDeployment(t *testing.T) {
	t.Helper()

	runCloudCommand(t, cloudDefaultTimeout, "kubectl", h.kubectlNamespaceArgs("rollout", "restart", "deployment/sample-client")...)
	waitForDeploymentAvailable(t, h.repoRoot, h.kubeContext, h.namespace, "sample-client", cloudDefaultTimeout)
}

func (h *cloudHarness) patchClientLabels(t *testing.T, labels map[string]string) {
	t.Helper()

	runCloudCommand(t, cloudDefaultTimeout, "kubectl", h.kubectlNamespaceArgs("delete", "deployment", "sample-client", "--ignore-not-found=true", "--wait=true")...)
	h.ensureClientWorkload(t, labels)
}

func (h *cloudHarness) clientPodIPs(t *testing.T) []string {
	t.Helper()

	output := runCloudCommand(
		t,
		cloudCommandTimeout,
		"kubectl",
		h.kubectlNamespaceArgs("get", "pods", "-l", "app=sample-client", "-o", "json")...,
	)

	var response struct {
		Items []struct {
			Status struct {
				PodIP string `json:"podIP"`
			} `json:"status"`
		} `json:"items"`
	}
	if err := json.Unmarshal([]byte(output), &response); err != nil {
		t.Fatalf("decode pod list: %v", err)
	}

	ips := make([]string, 0, len(response.Items))
	for _, item := range response.Items {
		if item.Status.PodIP != "" {
			ips = append(ips, item.Status.PodIP)
		}
	}
	sort.Strings(ips)
	return ips
}

func (h *cloudHarness) requireAllClientPodsAllowed(t *testing.T, path string) {
	t.Helper()
	h.requireHTTPAllowed(t, path)

	h.waitFor(0, func() bool {
		output := runCloudCommand(
			t,
			cloudCommandTimeout,
			"kubectl",
			h.kubectlNamespaceArgs("get", "pods", "-l", "app=sample-client", "-o", "json")...,
		)

		var response struct {
			Items []struct {
				Metadata struct {
					Name string `json:"name"`
				} `json:"metadata"`
			} `json:"items"`
		}
		if err := json.Unmarshal([]byte(output), &response); err != nil {
			return false
		}
		if len(response.Items) == 0 {
			return false
		}
		for _, item := range response.Items {
			if item.Metadata.Name == "" {
				return false
			}
			for _, endpoint := range h.cfg.metricsEndpoints {
				status := strings.TrimSpace(h.execPod(
					t,
					item.Metadata.Name,
					"sh",
					"-c",
					fmt.Sprintf(
						"curl -sS --proxy %s -o /dev/null -w '%%{http_code}' %s",
						shellQuote(h.proxyURLForMetricsEndpoint(t, endpoint)),
						shellQuote(h.targetURLForPath(t, path)),
					),
				))
				if status != "200" {
					return false
				}
			}
		}
		return true
	})
}

func (h *cloudHarness) requireRemovedPodIPsDrained(t *testing.T, previousPodIPs []string) {
	t.Helper()

	h.waitFor(0, func() bool {
		currentIPs := h.clientPodIPs(t)
		current := make(map[string]struct{}, len(currentIPs))
		for _, ip := range currentIPs {
			current[ip] = struct{}{}
		}
		removed := 0
		for _, ip := range previousPodIPs {
			if _, ok := current[ip]; ok {
				continue
			}
			removed++
		}
		return removed > 0
	})
}

func (h *cloudHarness) kubectlArgs(args ...string) []string {
	if h.kubeContext == "" {
		return append([]string(nil), args...)
	}

	commandArgs := []string{"--context", h.kubeContext}
	commandArgs = append(commandArgs, args...)
	return commandArgs
}

func (h *cloudHarness) kubectlNamespaceArgs(args ...string) []string {
	commandArgs := h.kubectlArgs("-n", h.namespace)
	commandArgs = append(commandArgs, args...)
	return commandArgs
}

func joinCloudObjectPath(parts ...string) string {
	segments := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.Trim(part, "/"); trimmed != "" {
			segments = append(segments, trimmed)
		}
	}
	return strings.Join(segments, "/")
}

func (h *cloudHarness) clientWorkloadYAML(labels map[string]string) string {
	labelPairs := make([]string, 0, len(labels))
	for key, value := range labels {
		labelPairs = append(labelPairs, fmt.Sprintf("        %s: %s", key, quoteYAML(value)))
	}
	sort.Strings(labelPairs)
	selectorPairs := make([]string, 0, len(labels))
	for key, value := range labels {
		selectorPairs = append(selectorPairs, fmt.Sprintf("      %s: %s", key, quoteYAML(value)))
	}
	sort.Strings(selectorPairs)

	return fmt.Sprintf(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: sample-client
spec:
  replicas: 1
  selector:
    matchLabels:
%s
  template:
    metadata:
      labels:
%s
    spec:
      containers:
        - name: curl
          image: curlimages/curl:8.8.0
          command: ["sleep", "infinity"]
          env:
            - name: HTTP_PROXY
              value: %s
            - name: HTTPS_PROXY
              value: %s
            - name: NO_PROXY
              value: %s
`,
		strings.Join(selectorPairs, "\n"),
		strings.Join(labelPairs, "\n"),
		quoteYAML(h.cfg.proxyURL),
		quoteYAML(h.cfg.proxyURL),
		quoteYAML("127.0.0.1,localhost,.localhost,kubernetes.default.svc,kubernetes.default.svc.cluster.local,.svc,.cluster.local,169.254.169.254"),
	)
}

func joinQuotedYAML(values []string) string {
	quoted := make([]string, 0, len(values))
	for _, value := range values {
		quoted = append(quoted, quoteYAML(value))
	}
	return strings.Join(quoted, ", ")
}

func quoteYAML(value string) string {
	return fmt.Sprintf("%q", value)
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'"
}

func (h *cloudHarness) targetURLForPath(t *testing.T, path string) string {
	t.Helper()

	base, err := url.Parse(h.cfg.targetURL)
	if err != nil {
		t.Fatalf("parse target URL %q: %v", h.cfg.targetURL, err)
	}
	if strings.TrimSpace(path) == "" {
		return base.String()
	}
	base.Path = path
	base.RawPath = ""
	base.RawQuery = ""
	base.Fragment = ""
	return base.String()
}

func currentCloudKubeContext(t *testing.T) string {
	t.Helper()

	if value := strings.TrimSpace(os.Getenv("CLOUD_E2E_KUBE_CONTEXT")); value != "" {
		return value
	}

	output, err := runCloudCommandOutput(cloudCommandTimeout, "kubectl", "config", "current-context")
	if err != nil {
		t.Skipf("kubectl current-context unavailable: %v\n%s", err, output)
	}

	value := strings.TrimSpace(output)
	if value == "" {
		t.Skip("kubectl current-context returned empty context")
	}
	return value
}

func (h *cloudHarness) expectedPolicyCount(t *testing.T) float64 {
	t.Helper()

	if !h.baselineSet {
		h.baselinePolicies = h.waitForConsistentRemotePolicyCount(t)
		h.baselineSet = true
	}
	return h.baselinePolicies + float64(len(h.listPolicyObjects(t)))
}

func (h *cloudHarness) currentRemotePolicyCount(t *testing.T) float64 {
	t.Helper()

	var value float64
	for idx, endpoint := range h.cfg.metricsEndpoints {
		metrics := h.metricsBody(t, endpoint)
		got, ok := metricValueOrZero(metrics, "aegis_policy_discovery_policies_active", map[string]string{
			"provider": "azure",
			"source":   "azure-policies",
		})
		if !ok {
			t.Fatalf("missing remote policy count metric for endpoint %s", endpoint)
		}
		if idx == 0 {
			value = got
			continue
		}
		if got != value {
			return -1
		}
	}
	return value
}

func (h *cloudHarness) waitForConsistentRemotePolicyCount(t *testing.T) float64 {
	t.Helper()

	var value float64
	h.waitFor(0, func() bool {
		value = h.currentRemotePolicyCount(t)
		return value >= 0
	})
	return value
}

func (h *cloudHarness) proxyURLForMetricsEndpoint(t *testing.T, endpoint string) string {
	t.Helper()

	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		t.Fatalf("split metrics endpoint %q: %v", endpoint, err)
	}
	return fmt.Sprintf("http://%s:3128", host)
}

func waitForCloudNamespaceDeleted(kubeContext string, namespace string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		_, err := runCloudCommandOutput(
			10*time.Second,
			"kubectl",
			cloudKubectlArgs(kubeContext, "get", "namespace", namespace)...,
		)
		if err != nil {
			return true
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

func cloudKubectlArgs(kubeContext string, args ...string) []string {
	if strings.TrimSpace(kubeContext) == "" {
		return append([]string(nil), args...)
	}

	commandArgs := []string{"--context", strings.TrimSpace(kubeContext)}
	commandArgs = append(commandArgs, args...)
	return commandArgs
}

func runCloudCommand(t *testing.T, timeout time.Duration, name string, args ...string) string {
	t.Helper()

	output, err := runCloudCommandOutput(timeout, name, args...)
	if err != nil {
		t.Fatalf("%s %s failed: %v\n%s", name, strings.Join(args, " "), err, output)
	}
	return output
}

func runCloudCommandOutput(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	output := strings.TrimSpace(stdout.String())
	errText := strings.TrimSpace(stderr.String())
	if errText != "" {
		if output != "" {
			output += "\n"
		}
		output += errText
	}
	if ctx.Err() == context.DeadlineExceeded {
		if output != "" {
			output += "\n"
		}
		output += fmt.Sprintf("command timed out after %s", timeout)
	}

	return output, err
}
