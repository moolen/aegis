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

func TestLoadRejectsHalfConfiguredProxyCA(t *testing.T) {
	_, err := Load(bytes.NewReader([]byte(`proxy:
  listen: ":3128"
  ca:
    certFile: /tmp/ca.crt
metrics:
  listen: ":9090"
`)))
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestLoadRejectsInvalidProxyProtocolHeaderTimeout(t *testing.T) {
	_, err := Load(bytes.NewReader([]byte(`proxy:
  listen: ":3128"
  proxyProtocol:
    enabled: true
    headerTimeout: 0s
metrics:
  listen: ":9090"
`)))
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestLoadRejectsNegativeMaxConcurrentConnectionsPerIdentity(t *testing.T) {
	_, err := Load(bytes.NewReader([]byte(`proxy:
  listen: ":3128"
  connectionLimits:
    maxConcurrentPerIdentity: -1
`)))
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestLoadAcceptsMaxConcurrentConnectionsPerIdentity(t *testing.T) {
	cfg, err := Load(bytes.NewReader([]byte(`proxy:
  listen: ":3128"
  connectionLimits:
    maxConcurrentPerIdentity: 7
`)))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Proxy.ConnectionLimits.MaxConcurrentPerIdentity != 7 {
		t.Fatalf("maxConcurrentPerIdentity = %d, want 7", cfg.Proxy.ConnectionLimits.MaxConcurrentPerIdentity)
	}
}

func TestLoadDefaultsProxyEnforcementToEnforce(t *testing.T) {
	cfg, err := Load(bytes.NewReader([]byte(`proxy:
  listen: ":3128"
`)))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Proxy.Enforcement != EnforcementEnforce {
		t.Fatalf("proxy enforcement = %q, want %q", cfg.Proxy.Enforcement, EnforcementEnforce)
	}
}

func TestLoadAcceptsAdminToken(t *testing.T) {
	cfg, err := Load(bytes.NewReader([]byte(`proxy:
  listen: ":3128"
admin:
  token: secret-token
`)))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Admin.Token != "secret-token" {
		t.Fatalf("admin token = %q, want %q", cfg.Admin.Token, "secret-token")
	}
}

func TestLoadRejectsWhitespaceOnlyAdminToken(t *testing.T) {
	_, err := Load(bytes.NewReader([]byte("proxy:\n  listen: \":3128\"\nadmin:\n  token: \"   \"\n")))
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestLoadRejectsInvalidProxyEnforcementMode(t *testing.T) {
	_, err := Load(bytes.NewReader([]byte(`proxy:
  listen: ":3128"
  enforcement: block
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

func TestLoadRejectsNonPositiveShutdownGracePeriod(t *testing.T) {
	_, err := Load(bytes.NewReader([]byte(`proxy:
  listen: ":3128"
shutdown:
  gracePeriod: 0s
`)))
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestLoadValidDNSRebindingProtectionConfig(t *testing.T) {
	cfg, err := Load(bytes.NewReader([]byte(`proxy:
  listen: ":3128"
dns:
  cache_ttl: 30s
  timeout: 5s
  rebindingProtection:
    allowedHostPatterns: ["*.svc.cluster.local"]
    allowedCIDRs: ["127.0.0.0/8", "10.0.0.0/8"]
`)))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(cfg.DNS.RebindingProtection.AllowedHostPatterns) != 1 {
		t.Fatalf("allowed host patterns = %d, want 1", len(cfg.DNS.RebindingProtection.AllowedHostPatterns))
	}
	if len(cfg.DNS.RebindingProtection.AllowedCIDRs) != 2 {
		t.Fatalf("allowed CIDRs = %d, want 2", len(cfg.DNS.RebindingProtection.AllowedCIDRs))
	}
}

func TestLoadRejectsEmptyDNSRebindingProtectionHostPattern(t *testing.T) {
	_, err := Load(bytes.NewReader([]byte(`proxy:
  listen: ":3128"
dns:
  cache_ttl: 30s
  timeout: 5s
  rebindingProtection:
    allowedHostPatterns: [" "]
`)))
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestLoadRejectsInvalidDNSRebindingProtectionCIDR(t *testing.T) {
	_, err := Load(bytes.NewReader([]byte(`proxy:
  listen: ":3128"
dns:
  cache_ttl: 30s
  timeout: 5s
  rebindingProtection:
    allowedCIDRs: ["not-a-cidr"]
`)))
	if err == nil {
		t.Fatal("expected validation error")
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

func TestLoadValidEC2DiscoveryConfig(t *testing.T) {
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
  ec2:
    - name: production-ec2
      region: eu-central-1
      tagFilters:
        - key: "aegis-managed"
          values: ["true"]
      pollInterval: 30s
`)))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(cfg.Discovery.EC2) != 1 {
		t.Fatalf("ec2 entries = %d, want 1", len(cfg.Discovery.EC2))
	}
	entry := cfg.Discovery.EC2[0]
	if entry.Name != "production-ec2" {
		t.Fatalf("entry name = %q, want %q", entry.Name, "production-ec2")
	}
	if entry.Region != "eu-central-1" {
		t.Fatalf("entry region = %q, want %q", entry.Region, "eu-central-1")
	}
	if len(entry.TagFilters) != 1 {
		t.Fatalf("tag filters = %d, want 1", len(entry.TagFilters))
	}
	if entry.PollInterval == nil {
		t.Fatal("entry pollInterval is nil, want 30s")
	}
	if *entry.PollInterval != 30*time.Second {
		t.Fatalf("entry pollInterval = %s, want %s", *entry.PollInterval, 30*time.Second)
	}
}

func TestLoadRejectsEC2DiscoveryWithoutName(t *testing.T) {
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
  ec2:
    - region: eu-central-1
`)))
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestLoadRejectsEC2DiscoveryWithoutRegion(t *testing.T) {
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
  ec2:
    - name: production-ec2
`)))
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestLoadRejectsEC2DiscoveryWithoutTagFilterKey(t *testing.T) {
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
  ec2:
    - name: production-ec2
      region: eu-central-1
      tagFilters:
        - values: ["true"]
`)))
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestLoadRejectsEmptyEC2TagFilterValue(t *testing.T) {
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
  ec2:
    - name: production-ec2
      region: eu-central-1
      tagFilters:
        - key: "aegis-managed"
          values: ["true", ""]
`)))
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestLoadRejectsNonPositiveEC2PollInterval(t *testing.T) {
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
  ec2:
    - name: production-ec2
      region: eu-central-1
      pollInterval: 0s
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
	if !bytes.Contains(data, []byte("kubernetes:")) {
		t.Fatal("example config does not include discovery.kubernetes section")
	}
	if !bytes.Contains(data, []byte("ec2:")) {
		t.Fatal("example config does not include discovery.ec2 section")
	}
	cfg, err := Load(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(cfg.Discovery.Kubernetes) != 0 {
		t.Fatalf("example config should keep discovery disabled for local runs, got %d providers", len(cfg.Discovery.Kubernetes))
	}
	if len(cfg.Discovery.EC2) != 0 {
		t.Fatalf("example config should keep ec2 discovery disabled for local runs, got %d providers", len(cfg.Discovery.EC2))
	}
}
