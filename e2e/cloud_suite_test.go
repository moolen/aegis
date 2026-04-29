//go:build cloud_e2e

package e2e

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	cloudNamespacePrefix = "aegis-cloud-e2e"
	cloudDefaultTimeout  = 5 * time.Minute
	cloudDefaultPoll     = 2 * time.Second
)

var cloudRunCounter atomic.Uint64
var cloudRunSeed = sanitizeDNSLabel(strconv.FormatInt(time.Now().UTC().UnixNano(), 36))

type cloudConfig struct {
	proxyURL         string
	targetURL        string
	targetHTTPSURL   string
	storageAccount   string
	policyContainer  string
	policyPrefix     string
	metricsEndpoints []string
	probeNamespace   string
	probeTarget      string
	namespacePrefix  string
	timeout          time.Duration
	pollInterval     time.Duration
	keepArtifacts    bool
}

type cloudRunNames struct {
	namespace string
	prefix    string
}

func TestCloudConfigRequiresEssentialEnvironment(t *testing.T) {
	t.Setenv("AEGIS_PROXY_URL", "")
	t.Setenv("AZURE_STORAGE_ACCOUNT_NAME", "")

	_, err := loadCloudConfigFromEnv()
	if err == nil {
		t.Fatal("loadCloudConfigFromEnv() error = nil, want missing environment error")
	}
}

func TestCloudConfigLoadsMetricsEndpoints(t *testing.T) {
	t.Setenv("AEGIS_PROXY_URL", "http://proxy.aegis.internal:3128")
	t.Setenv("AEGIS_TARGET_URL", "http://nginx.aegis.internal/static/allowed")
	t.Setenv("AEGIS_TARGET_HTTPS_URL", "https://nginx.aegis.internal/static/allowed")
	t.Setenv("AZURE_STORAGE_ACCOUNT_NAME", "acct")
	t.Setenv("AZURE_POLICY_CONTAINER", "policies")
	t.Setenv("AZURE_POLICY_PREFIX", "tenants/e2e/")
	t.Setenv("AEGIS_METRICS_ENDPOINTS", "10.0.0.4:9090,10.0.0.5:9090")

	cfg, err := loadCloudConfigFromEnv()
	if err != nil {
		t.Fatalf("loadCloudConfigFromEnv() error = %v", err)
	}
	if len(cfg.metricsEndpoints) != 2 {
		t.Fatalf("metrics endpoints = %d, want 2", len(cfg.metricsEndpoints))
	}
}

func TestCloudRunNamesStayIsolated(t *testing.T) {
	first := newCloudRunNames("TestBlobLifecycle", 1)
	second := newCloudRunNames("TestBlobLifecycle", 2)

	if first.namespace == second.namespace {
		t.Fatalf("namespace = %q for both runs, want unique values", first.namespace)
	}
	if first.prefix == second.prefix {
		t.Fatalf("prefix = %q for both runs, want unique values", first.prefix)
	}
}

func TestCloudMetricsEndpointListDropsEmptyValues(t *testing.T) {
	t.Setenv("AEGIS_PROXY_URL", "http://proxy")
	t.Setenv("AEGIS_TARGET_URL", "http://target")
	t.Setenv("AEGIS_TARGET_HTTPS_URL", "https://target")
	t.Setenv("AZURE_STORAGE_ACCOUNT_NAME", "acct")
	t.Setenv("AZURE_POLICY_CONTAINER", "policies")
	t.Setenv("AZURE_POLICY_PREFIX", "prefix")
	t.Setenv("AEGIS_METRICS_ENDPOINTS", "10.0.0.4:9090, ,10.0.0.5:9090")

	cfg, err := loadCloudConfigFromEnv()
	if err != nil {
		t.Fatalf("loadCloudConfigFromEnv() error = %v", err)
	}
	if got, want := len(cfg.metricsEndpoints), 2; got != want {
		t.Fatalf("metrics endpoints = %d, want %d", got, want)
	}
}

func TestCloudPolicyObjectKeyUsesRunPrefix(t *testing.T) {
	h := cloudHarness{prefix: "runs/blob-01"}
	if got, want := h.policyObjectKey("allow.yaml"), "runs/blob-01/allow.yaml"; got != want {
		t.Fatalf("policy object key = %q, want %q", got, want)
	}
}

func TestCloudTargetURLForPathReplacesPath(t *testing.T) {
	h := cloudHarness{
		cfg: cloudConfig{
			targetURL: "http://nginx.aegis.internal/static/allowed?old=1",
		},
	}

	if got, want := h.targetURLForPath(t, "/healthz"), "http://nginx.aegis.internal/healthz"; got != want {
		t.Fatalf("target URL = %q, want %q", got, want)
	}
}

func TestCloudAllowHTTPPolicyYAMLUsesRunScopedName(t *testing.T) {
	h := cloudHarness{prefix: "aegis-cloud-e2e/test-run-01"}

	body := h.allowHTTPPolicyYAML("sample-client", []string{"ns-a"})
	if !strings.Contains(body, `name: "allow-http-aegis-cloud-e2e-test-run-01"`) {
		t.Fatalf("policy body missing run-scoped name:\n%s", body)
	}
}

func loadCloudConfigFromEnv() (cloudConfig, error) {
	required := map[string]string{
		"AEGIS_PROXY_URL":            strings.TrimSpace(os.Getenv("AEGIS_PROXY_URL")),
		"AEGIS_TARGET_URL":           strings.TrimSpace(os.Getenv("AEGIS_TARGET_URL")),
		"AEGIS_TARGET_HTTPS_URL":     strings.TrimSpace(os.Getenv("AEGIS_TARGET_HTTPS_URL")),
		"AZURE_STORAGE_ACCOUNT_NAME": strings.TrimSpace(os.Getenv("AZURE_STORAGE_ACCOUNT_NAME")),
		"AZURE_POLICY_CONTAINER":     strings.TrimSpace(os.Getenv("AZURE_POLICY_CONTAINER")),
		"AZURE_POLICY_PREFIX":        strings.TrimSpace(os.Getenv("AZURE_POLICY_PREFIX")),
		"AEGIS_METRICS_ENDPOINTS":    strings.TrimSpace(os.Getenv("AEGIS_METRICS_ENDPOINTS")),
	}
	for key, value := range required {
		if value == "" {
			return cloudConfig{}, fmt.Errorf("%s is required", key)
		}
	}

	timeout := cloudDefaultTimeout
	if raw := strings.TrimSpace(os.Getenv("CLOUD_E2E_TIMEOUT")); raw != "" {
		parsed, err := time.ParseDuration(raw)
		if err != nil {
			return cloudConfig{}, fmt.Errorf("parse CLOUD_E2E_TIMEOUT: %w", err)
		}
		timeout = parsed
	}

	pollInterval := cloudDefaultPoll
	if raw := strings.TrimSpace(os.Getenv("CLOUD_E2E_POLL_INTERVAL")); raw != "" {
		parsed, err := time.ParseDuration(raw)
		if err != nil {
			return cloudConfig{}, fmt.Errorf("parse CLOUD_E2E_POLL_INTERVAL: %w", err)
		}
		pollInterval = parsed
	}

	metricsEndpoints := splitCloudList(required["AEGIS_METRICS_ENDPOINTS"])
	if len(metricsEndpoints) == 0 {
		return cloudConfig{}, fmt.Errorf("AEGIS_METRICS_ENDPOINTS is required")
	}

	return cloudConfig{
		proxyURL:         required["AEGIS_PROXY_URL"],
		targetURL:        required["AEGIS_TARGET_URL"],
		targetHTTPSURL:   required["AEGIS_TARGET_HTTPS_URL"],
		storageAccount:   required["AZURE_STORAGE_ACCOUNT_NAME"],
		policyContainer:  required["AZURE_POLICY_CONTAINER"],
		policyPrefix:     strings.Trim(required["AZURE_POLICY_PREFIX"], "/"),
		metricsEndpoints: metricsEndpoints,
		probeNamespace:   firstNonEmpty(os.Getenv("CLOUD_E2E_PROBE_NAMESPACE"), "aegis-cloud"),
		probeTarget:      firstNonEmpty(os.Getenv("CLOUD_E2E_PROBE_TARGET"), "deploy/sample-client"),
		namespacePrefix:  firstNonEmpty(os.Getenv("CLOUD_E2E_NAMESPACE_PREFIX"), cloudNamespacePrefix),
		timeout:          timeout,
		pollInterval:     pollInterval,
		keepArtifacts:    strings.EqualFold(strings.TrimSpace(os.Getenv("CLOUD_E2E_KEEP_ARTIFACTS")), "true"),
	}, nil
}

func newCloudRunNames(testName string, seq uint64) cloudRunNames {
	slug := sanitizeDNSLabel(testName)
	if slug == "" {
		slug = "test"
	}
	suffix := fmt.Sprintf("%s-%02d", cloudRunSeed, seq)

	return cloudRunNames{
		namespace: buildDNSLabel(cloudNamespacePrefix, slug, suffix, 63),
		prefix:    fmt.Sprintf("%s/%s-%s", strings.Trim(cloudNamespacePrefix, "-"), slug, suffix),
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func mustCloudConfig(t *testing.T) cloudConfig {
	t.Helper()

	cfg, err := loadCloudConfigFromEnv()
	if err != nil {
		t.Skipf("cloud_e2e environment not configured: %v", err)
	}
	if _, err := url.Parse(cfg.proxyURL); err != nil {
		t.Fatalf("proxy URL parse error: %v", err)
	}

	return cfg
}

func splitCloudList(value string) []string {
	parts := strings.Split(value, ",")
	items := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		items = append(items, part)
	}
	return items
}
