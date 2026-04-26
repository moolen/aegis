package helm_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestDeploymentChangesConfigChecksumWhenConfigChanges(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	valuesA := filepath.Join(dir, "values-a.yaml")
	valuesB := filepath.Join(dir, "values-b.yaml")

	writeValues := func(path, policyName string) {
		t.Helper()
		const tpl = `config:
  proxy:
    listen: ":3128"
  metrics:
    listen: ":9090"
  dns:
    cache_ttl: 30s
    timeout: 5s
    servers: []
    rebindingProtection:
      allowedHostPatterns: []
      allowedCIDRs: []
  discovery:
    kubernetes: []
    ec2: []
  policies:
    - name: %s
      subjects:
        cidrs:
          - "0.0.0.0/0"
      egress:
        - fqdn: "example.com"
          ports: [443]
          tls:
            mode: passthrough
`
		if err := os.WriteFile(path, []byte(fmt.Sprintf(tpl, policyName)), 0o644); err != nil {
			t.Fatalf("write values file %s: %v", path, err)
		}
	}

	writeValues(valuesA, "policy-a")
	writeValues(valuesB, "policy-b")

	renderA := helmTemplate(t, valuesA)
	renderB := helmTemplate(t, valuesB)

	checksumA := deploymentConfigChecksum(t, renderA)
	checksumB := deploymentConfigChecksum(t, renderB)

	if checksumA == "" || checksumB == "" {
		t.Fatalf("expected checksum/config annotation in both renders, got %q and %q", checksumA, checksumB)
	}
	if checksumA == checksumB {
		t.Fatalf("expected checksum/config annotation to change when config changes, both renders had %q", checksumA)
	}
}

func helmTemplate(t *testing.T, valuesFile string) string {
	t.Helper()

	cmd := exec.Command("helm", "template", "aegis", "./deploy/helm", "-f", valuesFile)
	cmd.Dir = filepath.Join(repoRoot(t))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helm template failed: %v\n%s", err, out)
	}
	return string(out)
}

func deploymentConfigChecksum(t *testing.T, rendered string) string {
	t.Helper()

	deploymentDoc := yamlDocument(rendered, "Deployment", "aegis")
	re := regexp.MustCompile(`(?m)^\s+checksum/config:\s+"?([^"\n]+)"?\s*$`)
	match := re.FindStringSubmatch(deploymentDoc)
	if len(match) != 2 {
		return ""
	}
	return strings.TrimSpace(match[1])
}

func yamlDocument(rendered, kind, name string) string {
	docs := strings.Split(rendered, "\n---\n")
	for _, doc := range docs {
		if strings.Contains(doc, "kind: "+kind) && strings.Contains(doc, "name: "+name) {
			return doc
		}
	}
	return ""
}

func repoRoot(t *testing.T) string {
	t.Helper()

	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	return root
}
