package config

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadValidConfig(t *testing.T) {
	cfg, err := Load(bytes.NewReader([]byte(`proxy:
  listen: ":3128"
metrics:
  listen: ":9090"
dns:
  cache_ttl: 30s
  timeout: 5s
`)))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Proxy.Listen != ":3128" {
		t.Fatalf("unexpected proxy listen %q", cfg.Proxy.Listen)
	}
	if cfg.Metrics.Listen != ":9090" {
		t.Fatalf("unexpected metrics listen %q", cfg.Metrics.Listen)
	}
	if cfg.DNS.CacheTTL != 30*time.Second {
		t.Fatalf("unexpected cache TTL %s", cfg.DNS.CacheTTL)
	}
}

func TestLoadRejectsMissingProxyListen(t *testing.T) {
	_, err := Load(bytes.NewReader([]byte(`metrics:
  listen: ":9090"
`)))
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	_, err := Load(bytes.NewReader([]byte(`proxy:
  listen: ":3128"
unknown: true
`)))
	if err == nil {
		t.Fatal("expected unknown field error")
	}
}

func TestLoadValidPolicyConfig(t *testing.T) {
	cfg, err := Load(bytes.NewReader([]byte(`proxy:
  listen: ":3128"
policies:
  - name: allow-web
    identitySelector:
      matchLabels:
        app: web
    egress:
      - fqdn: "example.com"
        ports: [80]
        tls:
          mode: mitm
        http:
          allowedMethods: ["GET"]
          allowedPaths: ["/api/*"]
`)))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(cfg.Policies) != 1 {
		t.Fatalf("policies = %d, want 1", len(cfg.Policies))
	}
}

func TestLoadRejectsInvalidTLSMode(t *testing.T) {
	_, err := Load(bytes.NewReader([]byte(`proxy:
  listen: ":3128"
policies:
  - name: bad
    identitySelector:
      matchLabels: {}
    egress:
      - fqdn: "example.com"
        ports: [80]
        tls:
          mode: invalid
`)))
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestLoadRejectsHTTPRulesForPassthrough(t *testing.T) {
	_, err := Load(bytes.NewReader([]byte(`proxy:
  listen: ":3128"
policies:
  - name: bad
    identitySelector:
      matchLabels: {}
    egress:
      - fqdn: "example.com"
        ports: [443]
        tls:
          mode: passthrough
        http:
          allowedMethods: ["GET"]
`)))
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestLoadRejectsEmptyPolicyFQDN(t *testing.T) {
	_, err := Load(bytes.NewReader([]byte(`proxy:
  listen: ":3128"
policies:
  - name: bad
    identitySelector:
      matchLabels: {}
    egress:
      - fqdn: "   "
        ports: [80]
        tls:
          mode: mitm
`)))
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestLoadRejectsInvalidPolicyPort(t *testing.T) {
	_, err := Load(bytes.NewReader([]byte(`proxy:
  listen: ":3128"
policies:
  - name: bad
    identitySelector:
      matchLabels: {}
    egress:
      - fqdn: "example.com"
        ports: [70000]
        tls:
          mode: mitm
`)))
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestLoadRejectsEmptyHTTPMethodEntry(t *testing.T) {
	_, err := Load(bytes.NewReader([]byte(`proxy:
  listen: ":3128"
policies:
  - name: bad
    identitySelector:
      matchLabels: {}
    egress:
      - fqdn: "example.com"
        ports: [80]
        tls:
          mode: mitm
        http:
          allowedMethods: ["GET", ""]
`)))
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestLoadRejectsEmptyHTTPPathEntry(t *testing.T) {
	_, err := Load(bytes.NewReader([]byte(`proxy:
  listen: ":3128"
policies:
  - name: bad
    identitySelector:
      matchLabels: {}
    egress:
      - fqdn: "example.com"
        ports: [80]
        tls:
          mode: mitm
        http:
          allowedPaths: ["/api/*", " "]
`)))
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestLoadValidKubernetesDiscoveryConfig(t *testing.T) {
	cfg, err := Load(bytes.NewReader([]byte(`proxy:
  listen: ":3128"
policies:
  - name: allow-example
    identitySelector:
      matchLabels: {}
    egress:
      - fqdn: "example.com"
        ports: [80]
        tls:
          mode: mitm
discovery:
  kubernetes:
    - name: cluster-a
      kubeconfig: /tmp/kubeconfig
      namespaces: ["default", "prod"]
      resyncPeriod: 30s
`)))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(cfg.Discovery.Kubernetes) != 1 {
		t.Fatalf("kubernetes entries = %d, want 1", len(cfg.Discovery.Kubernetes))
	}
	entry := cfg.Discovery.Kubernetes[0]
	if entry.Name != "cluster-a" {
		t.Fatalf("entry name = %q, want %q", entry.Name, "cluster-a")
	}
	if entry.ResyncPeriod == nil {
		t.Fatal("entry resyncPeriod is nil, want 30s")
	}
	if *entry.ResyncPeriod != 30*time.Second {
		t.Fatalf("entry resyncPeriod = %s, want %s", *entry.ResyncPeriod, 30*time.Second)
	}
}

func TestLoadRejectsKubernetesDiscoveryWithoutName(t *testing.T) {
	_, err := Load(bytes.NewReader([]byte(`proxy:
  listen: ":3128"
policies:
  - name: allow-example
    identitySelector:
      matchLabels: {}
    egress:
      - fqdn: "example.com"
        ports: [80]
        tls:
          mode: mitm
discovery:
  kubernetes:
    - kubeconfig: /tmp/kubeconfig
`)))
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestLoadRejectsEmptyKubernetesNamespaceEntry(t *testing.T) {
	_, err := Load(bytes.NewReader([]byte(`proxy:
  listen: ":3128"
policies:
  - name: allow-example
    identitySelector:
      matchLabels: {}
    egress:
      - fqdn: "example.com"
        ports: [80]
        tls:
          mode: mitm
discovery:
  kubernetes:
    - name: cluster-a
      namespaces: ["default", ""]
`)))
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestLoadRejectsNonPositiveKubernetesResyncPeriod(t *testing.T) {
	_, err := Load(bytes.NewReader([]byte(`proxy:
  listen: ":3128"
policies:
  - name: allow-example
    identitySelector:
      matchLabels: {}
    egress:
      - fqdn: "example.com"
        ports: [80]
        tls:
          mode: mitm
discovery:
  kubernetes:
    - name: cluster-a
      resyncPeriod: 0s
`)))
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestExampleConfigIncludesDiscoverySection(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "aegis.example.yaml"))
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if !bytes.Contains(data, []byte("discovery:")) {
		t.Fatal("example config does not include discovery section")
	}
}
