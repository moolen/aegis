package config

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
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

func TestLoadRejectsInvalidUnknownIdentityPolicy(t *testing.T) {
	_, err := Load(bytes.NewReader([]byte(`proxy:
  listen: ":3128"
  unknownIdentityPolicy: maybe
`)))
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestLoadAcceptsUnknownIdentityDenyPolicy(t *testing.T) {
	cfg, err := Load(bytes.NewReader([]byte(`proxy:
  listen: ":3128"
  unknownIdentityPolicy: deny
`)))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Proxy.UnknownIdentityPolicy != "deny" {
		t.Fatalf("unknown identity policy = %q, want deny", cfg.Proxy.UnknownIdentityPolicy)
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
    subjects:
      kubernetes:
        discoveryNames: ["cluster-a"]
        namespaces: ["default"]
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
discovery:
  kubernetes:
    - name: cluster-a
      auth:
        provider: inCluster
`)))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(cfg.Policies) != 1 {
		t.Fatalf("policies = %d, want 1", len(cfg.Policies))
	}
}

func TestLoadAcceptsCIDRPolicySubjects(t *testing.T) {
	cfg, err := Load(bytes.NewReader([]byte(`proxy:
  listen: ":3128"
policies:
  - name: allow-office-and-cluster
    subjects:
      kubernetes:
        discoveryNames: ["cluster-a"]
        namespaces: ["default"]
        matchLabels:
          app: web
      cidrs:
        - " 10.20.0.1/16 "
        - "2001:db8:0:0::/64"
    egress:
      - fqdn: "example.com"
        ports: [443]
        tls:
          mode: passthrough
discovery:
  kubernetes:
    - name: cluster-a
      auth:
        provider: inCluster
`)))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	got := cfg.Policies[0].Subjects.CIDRs
	want := []string{"10.20.0.1/16", "2001:db8::/64"}
	if len(got) != len(want) {
		t.Fatalf("subjects.cidrs length = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("subjects.cidrs[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestLoadRejectsInvalidCIDRPolicySubjects(t *testing.T) {
	_, err := Load(bytes.NewReader([]byte(`proxy:
  listen: ":3128"
policies:
  - name: bad-cidrs
    subjects:
      cidrs:
        - " "
        - "not-a-cidr"
    egress:
      - fqdn: "example.com"
        ports: [443]
        tls:
          mode: passthrough
`)))
	if err == nil {
		t.Fatal("expected validation error")
	}
	if !strings.Contains(err.Error(), "subjects.cidrs") {
		t.Fatalf("error = %v, want subjects.cidrs validation error", err)
	}
}

func TestLoadAcceptsCIDROnlyPolicySubjects(t *testing.T) {
	cfg, err := Load(bytes.NewReader([]byte(`proxy:
  listen: ":3128"
policies:
  - name: allow-office
    subjects:
      cidrs:
        - "10.20.0.0/16"
    egress:
      - fqdn: "api.example.com"
        ports: [443]
        tls:
          mode: passthrough
`)))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(cfg.Policies) != 1 {
		t.Fatalf("policies = %d, want 1", len(cfg.Policies))
	}
	if len(cfg.Policies[0].Subjects.CIDRs) != 1 || cfg.Policies[0].Subjects.CIDRs[0] != "10.20.0.0/16" {
		t.Fatalf("subjects.cidrs = %v, want [10.20.0.0/16]", cfg.Policies[0].Subjects.CIDRs)
	}
}

func TestLoadRejectsInvalidTLSMode(t *testing.T) {
	_, err := Load(bytes.NewReader([]byte(`proxy:
  listen: ":3128"
policies:
  - name: bad
    subjects:
      kubernetes:
        discoveryNames: ["cluster-a"]
        namespaces: ["default"]
        matchLabels: {}
    egress:
      - fqdn: "example.com"
        ports: [80]
        tls:
          mode: invalid
discovery:
  kubernetes:
    - name: cluster-a
      auth:
        provider: inCluster
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
    subjects:
      kubernetes:
        discoveryNames: ["cluster-a"]
        namespaces: ["default"]
        matchLabels: {}
    egress:
      - fqdn: "example.com"
        ports: [443]
        tls:
          mode: passthrough
        http:
          allowedMethods: ["GET"]
discovery:
  kubernetes:
    - name: cluster-a
      auth:
        provider: inCluster
`)))
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestLoadAcceptsPolicyLevelEnforcement(t *testing.T) {
	cfg, err := Load(bytes.NewReader([]byte(`proxy:
  listen: ":3128"
policies:
  - name: audited
    enforcement: audit
    subjects:
      kubernetes:
        discoveryNames: ["cluster-a"]
        namespaces: ["default"]
        matchLabels: {}
    egress:
      - fqdn: "example.com"
        ports: [443]
        tls:
          mode: passthrough
discovery:
  kubernetes:
    - name: cluster-a
      auth:
        provider: inCluster
`)))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Policies[0].Enforcement != "audit" {
		t.Fatalf("policy enforcement = %q, want audit", cfg.Policies[0].Enforcement)
	}
}

func TestLoadRejectsDuplicatePolicyNames(t *testing.T) {
	_, err := Load(bytes.NewReader([]byte(`proxy:
  listen: ":3128"
policies:
  - name: duplicate
    subjects:
      kubernetes:
        discoveryNames: ["cluster-a"]
        namespaces: ["default"]
        matchLabels: {}
    egress:
      - fqdn: "example.com"
        ports: [80]
        tls:
          mode: mitm
  - name: duplicate
    subjects:
      kubernetes:
        discoveryNames: ["cluster-a"]
        namespaces: ["default"]
        matchLabels: {}
    egress:
      - fqdn: "example.org"
        ports: [80]
        tls:
          mode: mitm
discovery:
  kubernetes:
    - name: cluster-a
      auth:
        provider: inCluster
`)))
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestLoadRejectsAdditionalCAWithoutPrimaryCA(t *testing.T) {
	_, err := Load(bytes.NewReader([]byte(`proxy:
  listen: ":3128"
  ca:
    additional:
      - certFile: /tmp/old.crt
        keyFile: /tmp/old.key
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
    subjects:
      kubernetes:
        discoveryNames: ["cluster-a"]
        namespaces: ["default"]
        matchLabels: {}
    egress:
      - fqdn: "   "
        ports: [80]
        tls:
          mode: mitm
discovery:
  kubernetes:
    - name: cluster-a
      auth:
        provider: inCluster
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
    subjects:
      kubernetes:
        discoveryNames: ["cluster-a"]
        namespaces: ["default"]
        matchLabels: {}
    egress:
      - fqdn: "example.com"
        ports: [70000]
        tls:
          mode: mitm
discovery:
  kubernetes:
    - name: cluster-a
      auth:
        provider: inCluster
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
    subjects:
      kubernetes:
        discoveryNames: ["cluster-a"]
        namespaces: ["default"]
        matchLabels: {}
    egress:
      - fqdn: "example.com"
        ports: [80]
        tls:
          mode: mitm
        http:
          allowedMethods: ["GET", ""]
discovery:
  kubernetes:
    - name: cluster-a
      auth:
        provider: inCluster
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
    subjects:
      kubernetes:
        discoveryNames: ["cluster-a"]
        namespaces: ["default"]
        matchLabels: {}
    egress:
      - fqdn: "example.com"
        ports: [80]
        tls:
          mode: mitm
        http:
          allowedPaths: ["/api/*", " "]
discovery:
  kubernetes:
    - name: cluster-a
      auth:
        provider: inCluster
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
    subjects:
      kubernetes:
        discoveryNames: ["cluster-a"]
        namespaces: ["default"]
        matchLabels: {}
    egress:
      - fqdn: "example.com"
        ports: [80]
        tls:
          mode: mitm
discovery:
  kubernetes:
    - name: cluster-a
      auth:
        provider: kubeconfig
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
    subjects:
      kubernetes:
        discoveryNames: ["cluster-a"]
        namespaces: ["default"]
        matchLabels: {}
    egress:
      - fqdn: "example.com"
        ports: [80]
        tls:
          mode: mitm
discovery:
  kubernetes:
    - auth:
        provider: kubeconfig
        kubeconfig: /tmp/kubeconfig
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
    subjects:
      kubernetes:
        discoveryNames: ["cluster-a"]
        namespaces: ["default"]
        matchLabels: {}
    egress:
      - fqdn: "example.com"
        ports: [80]
        tls:
          mode: mitm
discovery:
  kubernetes:
    - name: cluster-a
      auth:
        provider: inCluster
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
    subjects:
      kubernetes:
        discoveryNames: ["cluster-a"]
        namespaces: ["default"]
        matchLabels: {}
    egress:
      - fqdn: "example.com"
        ports: [80]
        tls:
          mode: mitm
discovery:
  kubernetes:
    - name: cluster-a
      auth:
        provider: inCluster
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
    subjects:
      ec2:
        discoveryNames: ["production-ec2"]
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
    subjects:
      ec2:
        discoveryNames: ["production-ec2"]
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
    subjects:
      ec2:
        discoveryNames: ["production-ec2"]
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
    subjects:
      ec2:
        discoveryNames: ["production-ec2"]
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
    subjects:
      ec2:
        discoveryNames: ["production-ec2"]
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
    subjects:
      ec2:
        discoveryNames: ["production-ec2"]
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

func TestLoadAcceptsKubernetesDiscoveryAuthProviders(t *testing.T) {
	tests := []struct {
		name string
		yaml string
	}{
		{
			name: "kubeconfig",
			yaml: `proxy:
  listen: ":3128"
discovery:
  kubernetes:
    - name: dev
      auth:
        provider: kubeconfig
        kubeconfig: /tmp/dev.kubeconfig
        context: dev
policies:
  - name: allow-dev
    subjects:
      kubernetes:
        discoveryNames: ["dev"]
        namespaces: ["default"]
        matchLabels:
          app: web
    egress:
      - fqdn: "example.com"
        ports: [443]
        tls:
          mode: passthrough
`,
		},
		{
			name: "eks",
			yaml: `proxy:
  listen: ":3128"
discovery:
  kubernetes:
    - name: cluster-a
      auth:
        provider: eks
        region: eu-central-1
        clusterName: cluster-a
policies:
  - name: allow-cluster-a
    subjects:
      kubernetes:
        discoveryNames: ["cluster-a"]
        namespaces: ["frontend"]
        matchLabels:
          app: frontend
    egress:
      - fqdn: "api.stripe.com"
        ports: [443]
        tls:
          mode: passthrough
`,
		},
		{
			name: "gke",
			yaml: `proxy:
  listen: ":3128"
discovery:
  kubernetes:
    - name: cluster-b
      auth:
        provider: gke
        project: prod-project
        location: europe-west1
        clusterName: cluster-b
policies:
  - name: allow-cluster-b
    subjects:
      kubernetes:
        discoveryNames: ["cluster-b"]
        namespaces: ["frontend"]
        matchLabels:
          app: frontend
    egress:
      - fqdn: "example.com"
        ports: [443]
        tls:
          mode: passthrough
`,
		},
		{
			name: "aks",
			yaml: `proxy:
  listen: ":3128"
discovery:
  kubernetes:
    - name: cluster-c
      auth:
        provider: aks
        subscriptionID: 00000000-0000-0000-0000-000000000000
        resourceGroup: rg-platform
        clusterName: cluster-c
policies:
  - name: allow-cluster-c
    subjects:
      kubernetes:
        discoveryNames: ["cluster-c"]
        namespaces: ["frontend"]
        matchLabels:
          app: frontend
    egress:
      - fqdn: "example.com"
        ports: [443]
        tls:
          mode: passthrough
`,
		},
		{
			name: "in-cluster",
			yaml: `proxy:
  listen: ":3128"
discovery:
  kubernetes:
    - name: in-cluster
      auth:
        provider: inCluster
policies:
  - name: allow-in-cluster
    subjects:
      kubernetes:
        discoveryNames: ["in-cluster"]
        namespaces: ["default"]
        matchLabels:
          app: web
    egress:
      - fqdn: "example.com"
        ports: [80]
        tls:
          mode: mitm
        http:
          allowedMethods: ["GET"]
          allowedPaths: ["/*"]
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Load(bytes.NewReader([]byte(tt.yaml))); err != nil {
				t.Fatalf("Load() error = %v", err)
			}
		})
	}
}

func TestLoadRejectsLegacyIdentitySelectorPolicySchema(t *testing.T) {
	_, err := Load(bytes.NewReader([]byte(`proxy:
  listen: ":3128"
policies:
  - name: legacy
    identitySelector:
      matchLabels:
        app: web
    egress:
      - fqdn: "example.com"
        ports: [443]
        tls:
          mode: passthrough
`)))
	if err == nil {
		t.Fatal("expected validation error")
	}
	if !strings.Contains(err.Error(), "policies[0].identitySelector is no longer supported; use subjects instead") {
		t.Fatalf("unexpected error = %v", err)
	}
}

func TestLoadRejectsLegacyKubernetesKubeconfigSchema(t *testing.T) {
	tests := []struct {
		name string
		yaml string
	}{
		{
			name: "explicit path",
			yaml: `proxy:
  listen: ":3128"
discovery:
  kubernetes:
    - name: cluster-a
      kubeconfig: /tmp/legacy.kubeconfig
      auth:
        provider: inCluster
policies:
  - name: allow-cluster-a
    subjects:
      kubernetes:
        discoveryNames: ["cluster-a"]
        namespaces: ["default"]
        matchLabels: {}
    egress:
      - fqdn: "example.com"
        ports: [443]
        tls:
          mode: passthrough
`,
		},
		{
			name: "whitespace only",
			yaml: `proxy:
  listen: ":3128"
discovery:
  kubernetes:
    - name: cluster-a
      kubeconfig: "   "
      auth:
        provider: inCluster
policies:
  - name: allow-cluster-a
    subjects:
      kubernetes:
        discoveryNames: ["cluster-a"]
        namespaces: ["default"]
        matchLabels: {}
    egress:
      - fqdn: "example.com"
        ports: [443]
        tls:
          mode: passthrough
`,
		},
		{
			name: "empty string",
			yaml: `proxy:
  listen: ":3128"
discovery:
  kubernetes:
    - name: cluster-a
      kubeconfig: ""
      auth:
        provider: inCluster
policies:
  - name: allow-cluster-a
    subjects:
      kubernetes:
        discoveryNames: ["cluster-a"]
        namespaces: ["default"]
        matchLabels: {}
    egress:
      - fqdn: "example.com"
        ports: [443]
        tls:
          mode: passthrough
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(bytes.NewReader([]byte(tt.yaml)))
			if err == nil {
				t.Fatal("expected validation error")
			}
			if !strings.Contains(err.Error(), "discovery.kubernetes[0].kubeconfig is no longer supported; use auth.provider: kubeconfig and auth.kubeconfig") {
				t.Fatalf("unexpected error = %v", err)
			}
		})
	}
}

func TestLoadRejectsUnknownKubernetesDiscoveryReference(t *testing.T) {
	_, err := Load(bytes.NewReader([]byte(`proxy:
  listen: ":3128"
discovery:
  kubernetes:
    - name: cluster-a
      auth:
        provider: inCluster
policies:
  - name: allow-cluster-b
    subjects:
      kubernetes:
        discoveryNames: ["cluster-b"]
        namespaces: ["default"]
        matchLabels: {}
    egress:
      - fqdn: "example.com"
        ports: [443]
        tls:
          mode: passthrough
`)))
	if err == nil {
		t.Fatal("expected validation error")
	}
	if !strings.Contains(err.Error(), `policies[0].subjects.kubernetes.discoveryNames[0] references unknown kubernetes discovery "cluster-b"`) {
		t.Fatalf("unexpected error = %v", err)
	}
}

func TestLoadRejectsUnknownEC2DiscoveryReference(t *testing.T) {
	_, err := Load(bytes.NewReader([]byte(`proxy:
  listen: ":3128"
discovery:
  ec2:
    - name: production-ec2
      region: eu-central-1
policies:
  - name: allow-missing-ec2
    subjects:
      ec2:
        discoveryNames: ["staging-ec2"]
    egress:
      - fqdn: "example.com"
        ports: [443]
        tls:
          mode: passthrough
`)))
	if err == nil {
		t.Fatal("expected validation error")
	}
	if !strings.Contains(err.Error(), `policies[0].subjects.ec2.discoveryNames[0] references unknown ec2 discovery "staging-ec2"`) {
		t.Fatalf("unexpected error = %v", err)
	}
}

func TestLoadRejectsDuplicateDiscoveryNamesAfterTrimming(t *testing.T) {
	_, err := Load(bytes.NewReader([]byte(`proxy:
  listen: ":3128"
discovery:
  kubernetes:
    - name: " cluster-a "
      auth:
        provider: inCluster
  ec2:
    - name: cluster-a
      region: eu-central-1
`)))
	if err == nil {
		t.Fatal("expected validation error")
	}
	if !strings.Contains(err.Error(), `discovery.ec2[0].name "cluster-a" must be unique across discovery providers`) {
		t.Fatalf("unexpected error = %v", err)
	}
}

func TestLoadNormalizesDiscoveryNamesAndSubjectReferences(t *testing.T) {
	cfg, err := Load(bytes.NewReader([]byte(`proxy:
  listen: ":3128"
discovery:
  kubernetes:
    - name: " cluster-a "
      auth:
        provider: inCluster
  ec2:
    - name: production-ec2
      region: eu-central-1
policies:
  - name: allow-kubernetes
    subjects:
      kubernetes:
        discoveryNames: ["cluster-a"]
        namespaces: ["default"]
        matchLabels: {}
    egress:
      - fqdn: "example.com"
        ports: [443]
        tls:
          mode: passthrough
  - name: allow-ec2
    subjects:
      ec2:
        discoveryNames: [" production-ec2 "]
    egress:
      - fqdn: "example.org"
        ports: [443]
        tls:
          mode: passthrough
`)))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Discovery.Kubernetes[0].Name != "cluster-a" {
		t.Fatalf("kubernetes discovery name = %q, want %q", cfg.Discovery.Kubernetes[0].Name, "cluster-a")
	}
	if cfg.Discovery.EC2[0].Name != "production-ec2" {
		t.Fatalf("ec2 discovery name = %q, want %q", cfg.Discovery.EC2[0].Name, "production-ec2")
	}
	if cfg.Policies[0].Subjects.Kubernetes.DiscoveryNames[0] != "cluster-a" {
		t.Fatalf("kubernetes subject discovery name = %q, want %q", cfg.Policies[0].Subjects.Kubernetes.DiscoveryNames[0], "cluster-a")
	}
	if cfg.Policies[1].Subjects.EC2.DiscoveryNames[0] != "production-ec2" {
		t.Fatalf("ec2 subject discovery name = %q, want %q", cfg.Policies[1].Subjects.EC2.DiscoveryNames[0], "production-ec2")
	}
}

func TestLoadRejectsMissingKubernetesAuthProviderFields(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		message string
	}{
		{
			name: "missing provider",
			yaml: `proxy:
  listen: ":3128"
discovery:
  kubernetes:
    - name: cluster-a
      auth: {}
policies:
  - name: allow-cluster-a
    subjects:
      kubernetes:
        discoveryNames: ["cluster-a"]
        namespaces: ["default"]
        matchLabels: {}
    egress:
      - fqdn: "example.com"
        ports: [443]
        tls:
          mode: passthrough
`,
			message: "discovery.kubernetes[0].auth.provider must be kubeconfig, inCluster, eks, gke, or aks",
		},
		{
			name: "kubeconfig missing kubeconfig",
			yaml: `proxy:
  listen: ":3128"
discovery:
  kubernetes:
    - name: cluster-a
      auth:
        provider: kubeconfig
policies:
  - name: allow-cluster-a
    subjects:
      kubernetes:
        discoveryNames: ["cluster-a"]
        namespaces: ["default"]
        matchLabels: {}
    egress:
      - fqdn: "example.com"
        ports: [443]
        tls:
          mode: passthrough
`,
			message: "discovery.kubernetes[0].auth.kubeconfig is required for kubeconfig auth",
		},
		{
			name: "eks missing fields",
			yaml: `proxy:
  listen: ":3128"
discovery:
  kubernetes:
    - name: cluster-a
      auth:
        provider: eks
        region: eu-central-1
policies:
  - name: allow-cluster-a
    subjects:
      kubernetes:
        discoveryNames: ["cluster-a"]
        namespaces: ["default"]
        matchLabels: {}
    egress:
      - fqdn: "example.com"
        ports: [443]
        tls:
          mode: passthrough
`,
			message: "discovery.kubernetes[0].auth.region and clusterName are required for eks auth",
		},
		{
			name: "gke missing fields",
			yaml: `proxy:
  listen: ":3128"
discovery:
  kubernetes:
    - name: cluster-a
      auth:
        provider: gke
        project: prod-project
policies:
  - name: allow-cluster-a
    subjects:
      kubernetes:
        discoveryNames: ["cluster-a"]
        namespaces: ["default"]
        matchLabels: {}
    egress:
      - fqdn: "example.com"
        ports: [443]
        tls:
          mode: passthrough
`,
			message: "discovery.kubernetes[0].auth.project, location, and clusterName are required for gke auth",
		},
		{
			name: "aks missing fields",
			yaml: `proxy:
  listen: ":3128"
discovery:
  kubernetes:
    - name: cluster-a
      auth:
        provider: aks
        subscriptionID: 00000000-0000-0000-0000-000000000000
policies:
  - name: allow-cluster-a
    subjects:
      kubernetes:
        discoveryNames: ["cluster-a"]
        namespaces: ["default"]
        matchLabels: {}
    egress:
      - fqdn: "example.com"
        ports: [443]
        tls:
          mode: passthrough
`,
			message: "discovery.kubernetes[0].auth.subscriptionID, resourceGroup, and clusterName are required for aks auth",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(bytes.NewReader([]byte(tt.yaml)))
			if err == nil {
				t.Fatal("expected validation error")
			}
			if !strings.Contains(err.Error(), tt.message) {
				t.Fatalf("unexpected error = %v", err)
			}
		})
	}
}

func TestLoadRejectsEmptyPolicySubjects(t *testing.T) {
	tests := []struct {
		name string
		yaml string
	}{
		{
			name: "empty subjects object",
			yaml: `proxy:
  listen: ":3128"
policies:
  - name: empty-subjects
    subjects: {}
    egress:
      - fqdn: "example.com"
        ports: [443]
        tls:
          mode: passthrough
`,
		},
		{
			name: "empty ec2 subject",
			yaml: `proxy:
  listen: ":3128"
policies:
  - name: empty-ec2
    subjects:
      ec2: {}
    egress:
      - fqdn: "example.com"
        ports: [443]
        tls:
          mode: passthrough
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(bytes.NewReader([]byte(tt.yaml)))
			if err == nil {
				t.Fatal("expected validation error")
			}
			if !strings.Contains(err.Error(), "policies[0].subjects must reference at least one discovery provider") {
				t.Fatalf("unexpected error = %v", err)
			}
		})
	}
}

func TestLoadRejectsKubernetesPolicySubjectsWithoutNamespaces(t *testing.T) {
	_, err := Load(bytes.NewReader([]byte(`proxy:
  listen: ":3128"
discovery:
  kubernetes:
    - name: cluster-a
      auth:
        provider: inCluster
policies:
  - name: missing-namespaces
    subjects:
      kubernetes:
        discoveryNames: ["cluster-a"]
        matchLabels:
          app: web
    egress:
      - fqdn: "example.com"
        ports: [443]
        tls:
          mode: passthrough
`)))
	if err == nil {
		t.Fatal("expected validation error")
	}
	if !strings.Contains(err.Error(), "policies[0].subjects.kubernetes.namespaces must contain at least one namespace") {
		t.Fatalf("unexpected error = %v", err)
	}
}

func TestLoadRejectsKubernetesPolicySubjectsWithoutDiscoveryNames(t *testing.T) {
	_, err := Load(bytes.NewReader([]byte(`proxy:
  listen: ":3128"
discovery:
  kubernetes:
    - name: cluster-a
      auth:
        provider: inCluster
  ec2:
    - name: production-ec2
      region: eu-central-1
policies:
  - name: missing-kubernetes-discovery-names
    subjects:
      kubernetes:
        namespaces: ["default"]
        matchLabels:
          app: web
      ec2:
        discoveryNames: ["production-ec2"]
    egress:
      - fqdn: "example.com"
        ports: [443]
        tls:
          mode: passthrough
`)))
	if err == nil {
		t.Fatal("expected validation error")
	}
	if !strings.Contains(err.Error(), "policies[0].subjects.kubernetes.discoveryNames must contain at least one discovery name") {
		t.Fatalf("unexpected error = %v", err)
	}
}

func TestLoadRejectsEC2PolicySubjectsWithoutDiscoveryNames(t *testing.T) {
	_, err := Load(bytes.NewReader([]byte(`proxy:
  listen: ":3128"
discovery:
  kubernetes:
    - name: cluster-a
      auth:
        provider: inCluster
  ec2:
    - name: production-ec2
      region: eu-central-1
policies:
  - name: missing-ec2-discovery-names
    subjects:
      kubernetes:
        discoveryNames: ["cluster-a"]
        namespaces: ["default"]
        matchLabels:
          app: web
      ec2: {}
    egress:
      - fqdn: "example.com"
        ports: [443]
        tls:
          mode: passthrough
`)))
	if err == nil {
		t.Fatal("expected validation error")
	}
	if !strings.Contains(err.Error(), "policies[0].subjects.ec2.discoveryNames must contain at least one discovery name") {
		t.Fatalf("unexpected error = %v", err)
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
