package config

import (
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	defaultMetricsListen = ":9090"
	defaultAdminListen   = "127.0.0.1:9091"
	defaultDNSCacheTTL   = 30 * time.Second
	defaultDNSTimeout    = 5 * time.Second
	defaultGracePeriod   = 10 * time.Second
	defaultProxyIdleTTL  = 2 * time.Minute
	EnforcementEnforce   = "enforce"
	EnforcementAudit     = "audit"
	UnknownIdentityAllow = "allow"
	UnknownIdentityDeny  = "deny"
)

type Config struct {
	Proxy     ProxyConfig     `yaml:"proxy"`
	Admin     AdminConfig     `yaml:"admin"`
	Metrics   MetricsConfig   `yaml:"metrics"`
	Pprof     PprofConfig     `yaml:"pprof"`
	DNS       DNSConfig       `yaml:"dns"`
	Shutdown  ShutdownConfig  `yaml:"shutdown"`
	Policies  []PolicyConfig  `yaml:"policies"`
	Discovery DiscoveryConfig `yaml:"discovery"`
}

type ProxyConfig struct {
	Enforcement           string                 `yaml:"enforcement"`
	UnknownIdentityPolicy string                 `yaml:"unknownIdentityPolicy"`
	Listen                string                 `yaml:"listen"`
	IdleTimeout           time.Duration          `yaml:"idleTimeout"`
	CA                    CAConfig               `yaml:"ca"`
	ProxyProtocol         ProxyProtocolConfig    `yaml:"proxyProtocol"`
	ConnectionLimits      ConnectionLimitsConfig `yaml:"connectionLimits"`
}

type CAConfig struct {
	CertFile   string         `yaml:"certFile"`
	KeyFile    string         `yaml:"keyFile"`
	Additional []AdditionalCA `yaml:"additional"`
	Cache      CACacheConfig  `yaml:"cache"`
}

type AdditionalCA struct {
	CertFile string `yaml:"certFile"`
	KeyFile  string `yaml:"keyFile"`
}

type CACacheConfig struct {
	MaxEntries int `yaml:"maxEntries"`
}

type ProxyProtocolConfig struct {
	Enabled       bool           `yaml:"enabled"`
	HeaderTimeout *time.Duration `yaml:"headerTimeout"`
	TrustedCIDRs  []string       `yaml:"trustedCIDRs"`
}

type ConnectionLimitsConfig struct {
	MaxConcurrentPerIdentity int `yaml:"maxConcurrentPerIdentity"`
}

type MetricsConfig struct {
	Listen string `yaml:"listen"`
}

type PprofConfig struct {
	Enabled bool   `yaml:"enabled"`
	Listen  string `yaml:"listen"`
}

type AdminConfig struct {
	Enabled bool   `yaml:"enabled"`
	Listen  string `yaml:"listen"`
	Token   string `yaml:"token"`
}

type ShutdownConfig struct {
	GracePeriod time.Duration `yaml:"gracePeriod"`
}

type DNSConfig struct {
	CacheTTL            time.Duration             `yaml:"cache_ttl"`
	Timeout             time.Duration             `yaml:"timeout"`
	Servers             []string                  `yaml:"servers"`
	RebindingProtection RebindingProtectionConfig `yaml:"rebindingProtection"`
}

type RebindingProtectionConfig struct {
	AllowedHostPatterns []string `yaml:"allowedHostPatterns"`
	AllowedCIDRs        []string `yaml:"allowedCIDRs"`
}

type DiscoveryConfig struct {
	Kubernetes []KubernetesDiscoveryConfig   `yaml:"kubernetes"`
	EC2        []EC2DiscoveryConfig          `yaml:"ec2"`
	Policies   []PolicyDiscoverySourceConfig `yaml:"policies"`
}

type KubernetesAuthConfig struct {
	Provider       string `yaml:"provider"`
	Kubeconfig     string `yaml:"kubeconfig"`
	Context        string `yaml:"context"`
	Region         string `yaml:"region"`
	Project        string `yaml:"project"`
	Location       string `yaml:"location"`
	ClusterName    string `yaml:"clusterName"`
	SubscriptionID string `yaml:"subscriptionID"`
	ResourceGroup  string `yaml:"resourceGroup"`
}

type KubernetesDiscoveryConfig struct {
	Name             string               `yaml:"name"`
	Auth             KubernetesAuthConfig `yaml:"auth"`
	Kubeconfig       string               `yaml:"-"`
	Namespaces       []string             `yaml:"namespaces"`
	ResyncPeriod     *time.Duration       `yaml:"resyncPeriod"`
	LegacyKubeconfig legacyStringField    `yaml:"kubeconfig,omitempty"`
}

type EC2DiscoveryConfig struct {
	Name         string               `yaml:"name"`
	Region       string               `yaml:"region"`
	TagFilters   []EC2TagFilterConfig `yaml:"tagFilters"`
	PollInterval *time.Duration       `yaml:"pollInterval"`
}

type PolicyDiscoverySourceConfig struct {
	Name         string                    `yaml:"name"`
	Provider     string                    `yaml:"provider"`
	Bucket       string                    `yaml:"bucket"`
	Prefix       string                    `yaml:"prefix"`
	PollInterval *time.Duration            `yaml:"pollInterval"`
	Auth         PolicyDiscoveryAuthConfig `yaml:"auth"`
}

type PolicyDiscoveryAuthConfig struct {
	Mode string `yaml:"mode"`
}

type EC2TagFilterConfig struct {
	Key    string   `yaml:"key"`
	Values []string `yaml:"values"`
}

type PolicyConfig struct {
	Name                   string                  `yaml:"name"`
	Enforcement            string                  `yaml:"enforcement"`
	Bypass                 bool                    `yaml:"bypass"`
	Subjects               PolicySubjectsConfig    `yaml:"subjects"`
	IdentitySelector       IdentitySelectorConfig  `yaml:"-"`
	LegacyIdentitySelector *IdentitySelectorConfig `yaml:"identitySelector,omitempty"`
	Egress                 []EgressRuleConfig      `yaml:"egress"`
}

type IdentitySelectorConfig struct {
	MatchLabels map[string]string `yaml:"matchLabels"`
}

type PolicySubjectsConfig struct {
	Kubernetes *KubernetesSubjectConfig `yaml:"kubernetes,omitempty"`
	EC2        *EC2SubjectConfig        `yaml:"ec2,omitempty"`
	CIDRs      []string                 `yaml:"cidrs,omitempty"`
}

type KubernetesSubjectConfig struct {
	DiscoveryNames []string          `yaml:"discoveryNames"`
	Namespaces     []string          `yaml:"namespaces"`
	MatchLabels    map[string]string `yaml:"matchLabels"`
}

type EC2SubjectConfig struct {
	DiscoveryNames []string `yaml:"discoveryNames"`
}

type legacyStringField struct {
	Value string
	Set   bool
}

func (f *legacyStringField) UnmarshalYAML(value *yaml.Node) error {
	f.Set = true
	if value.Tag == "!!null" {
		f.Value = ""
		return nil
	}
	return value.Decode(&f.Value)
}

type EgressRuleConfig struct {
	FQDN  string          `yaml:"fqdn"`
	Ports []int           `yaml:"ports"`
	TLS   TLSRuleConfig   `yaml:"tls"`
	HTTP  *HTTPRuleConfig `yaml:"http,omitempty"`
}

type TLSRuleConfig struct {
	Mode string `yaml:"mode"`
}

type HTTPRuleConfig struct {
	AllowedMethods []string `yaml:"allowedMethods"`
	AllowedPaths   []string `yaml:"allowedPaths"`
}

func Load(r io.Reader) (Config, error) {
	cfg := Config{
		Proxy: ProxyConfig{
			Enforcement:           EnforcementEnforce,
			UnknownIdentityPolicy: UnknownIdentityAllow,
			IdleTimeout:           defaultProxyIdleTTL,
		},
		Admin: AdminConfig{
			Listen: defaultAdminListen,
		},
		Metrics: MetricsConfig{Listen: defaultMetricsListen},
		DNS: DNSConfig{
			CacheTTL: defaultDNSCacheTTL,
			Timeout:  defaultDNSTimeout,
		},
		Shutdown: ShutdownConfig{
			GracePeriod: defaultGracePeriod,
		},
	}

	decoder := yaml.NewDecoder(r)
	decoder.KnownFields(true)

	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	if err := cfg.normalizeDiscoveryBindings(); err != nil {
		return Config{}, err
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	cfg.hydrateCompatibilityFields()

	return cfg, nil
}

func LoadFile(path string) (Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("open config: %w", err)
	}
	defer file.Close()

	return Load(file)
}

func (c Config) Validate() error {
	if c.Proxy.Listen == "" {
		return fmt.Errorf("proxy.listen is required")
	}
	switch NormalizeEnforcementMode(c.Proxy.Enforcement) {
	case EnforcementEnforce, EnforcementAudit:
	default:
		return fmt.Errorf("proxy.enforcement must be audit or enforce")
	}
	switch NormalizeUnknownIdentityPolicy(c.Proxy.UnknownIdentityPolicy) {
	case UnknownIdentityAllow, UnknownIdentityDeny:
	default:
		return fmt.Errorf("proxy.unknownIdentityPolicy must be allow or deny")
	}
	if (c.Proxy.CA.CertFile == "") != (c.Proxy.CA.KeyFile == "") {
		return fmt.Errorf("proxy.ca.certFile and proxy.ca.keyFile must be set together")
	}
	if c.Proxy.IdleTimeout <= 0 {
		return fmt.Errorf("proxy.idleTimeout must be greater than zero")
	}
	if len(c.Proxy.CA.Additional) > 0 && c.Proxy.CA.CertFile == "" {
		return fmt.Errorf("proxy.ca.additional requires proxy.ca.certFile and proxy.ca.keyFile")
	}
	for i, additional := range c.Proxy.CA.Additional {
		if (additional.CertFile == "") != (additional.KeyFile == "") {
			return fmt.Errorf("proxy.ca.additional[%d].certFile and proxy.ca.additional[%d].keyFile must be set together", i, i)
		}
		if additional.CertFile == "" {
			return fmt.Errorf("proxy.ca.additional[%d].certFile is required", i)
		}
	}
	if c.Proxy.ProxyProtocol.HeaderTimeout != nil && *c.Proxy.ProxyProtocol.HeaderTimeout <= 0 {
		return fmt.Errorf("proxy.proxyProtocol.headerTimeout must be greater than zero")
	}
	if c.Proxy.ProxyProtocol.Enabled && len(c.Proxy.ProxyProtocol.TrustedCIDRs) == 0 {
		return fmt.Errorf("proxy.proxyProtocol.trustedCIDRs must contain at least one CIDR when proxyProtocol is enabled")
	}
	for i, cidr := range c.Proxy.ProxyProtocol.TrustedCIDRs {
		if strings.TrimSpace(cidr) == "" {
			return fmt.Errorf("proxy.proxyProtocol.trustedCIDRs[%d] must not be empty", i)
		}
		if _, err := netip.ParsePrefix(cidr); err != nil {
			return fmt.Errorf("proxy.proxyProtocol.trustedCIDRs[%d] must be a valid CIDR: %w", i, err)
		}
	}
	if c.Proxy.ConnectionLimits.MaxConcurrentPerIdentity < 0 {
		return fmt.Errorf("proxy.connectionLimits.maxConcurrentPerIdentity must be greater than or equal to zero")
	}
	if c.Proxy.CA.Cache.MaxEntries < 0 {
		return fmt.Errorf("proxy.ca.cache.maxEntries must be greater than or equal to zero")
	}
	if c.Metrics.Listen == "" {
		return fmt.Errorf("metrics.listen is required")
	}
	if listenersConflict(c.Metrics.Listen, c.Proxy.Listen) {
		return fmt.Errorf("metrics.listen must differ from proxy.listen")
	}
	if c.Pprof.Enabled {
		if strings.TrimSpace(c.Pprof.Listen) == "" {
			return fmt.Errorf("pprof.listen is required when pprof is enabled")
		}
		if err := validateLocalhostListen(c.Pprof.Listen); err != nil {
			return fmt.Errorf("pprof.listen must be localhost-only: %w", err)
		}
		if listenersConflict(c.Pprof.Listen, c.Proxy.Listen) {
			return fmt.Errorf("pprof.listen must differ from proxy.listen")
		}
		if listenersConflict(c.Pprof.Listen, c.Metrics.Listen) {
			return fmt.Errorf("pprof.listen must differ from metrics.listen")
		}
		if c.Admin.Enabled && listenersConflict(c.Pprof.Listen, c.Admin.Listen) {
			return fmt.Errorf("pprof.listen must differ from admin.listen")
		}
	}
	if c.Admin.Token != "" && strings.TrimSpace(c.Admin.Token) == "" {
		return fmt.Errorf("admin.token must not be empty when set")
	}
	if c.Admin.Enabled {
		if strings.TrimSpace(c.Admin.Token) == "" {
			return fmt.Errorf("admin.token is required when admin is enabled")
		}
		if strings.TrimSpace(c.Admin.Listen) == "" {
			return fmt.Errorf("admin.listen is required when admin is enabled")
		}
		if err := validateLocalhostListen(c.Admin.Listen); err != nil {
			return fmt.Errorf("admin.listen must be localhost-only: %w", err)
		}
		if listenersConflict(c.Admin.Listen, c.Proxy.Listen) {
			return fmt.Errorf("admin.listen must differ from proxy.listen")
		}
		if listenersConflict(c.Admin.Listen, c.Metrics.Listen) {
			return fmt.Errorf("admin.listen must differ from metrics.listen")
		}
	}
	if c.Shutdown.GracePeriod <= 0 {
		return fmt.Errorf("shutdown.gracePeriod must be greater than zero")
	}
	if c.DNS.CacheTTL <= 0 {
		return fmt.Errorf("dns.cache_ttl must be greater than zero")
	}
	if c.DNS.Timeout <= 0 {
		return fmt.Errorf("dns.timeout must be greater than zero")
	}
	for i, server := range c.DNS.Servers {
		if server == "" {
			return fmt.Errorf("dns.servers[%d] must not be empty", i)
		}
	}
	for i, pattern := range c.DNS.RebindingProtection.AllowedHostPatterns {
		if strings.TrimSpace(pattern) == "" {
			return fmt.Errorf("dns.rebindingProtection.allowedHostPatterns[%d] must not be empty", i)
		}
		if strings.ContainsAny(pattern, "[]?\\") {
			return fmt.Errorf("dns.rebindingProtection.allowedHostPatterns[%d] only supports '*' wildcards", i)
		}
	}
	for i, cidr := range c.DNS.RebindingProtection.AllowedCIDRs {
		if strings.TrimSpace(cidr) == "" {
			return fmt.Errorf("dns.rebindingProtection.allowedCIDRs[%d] must not be empty", i)
		}
		if _, err := netip.ParsePrefix(cidr); err != nil {
			return fmt.Errorf("dns.rebindingProtection.allowedCIDRs[%d] must be a valid CIDR: %w", i, err)
		}
	}
	policyNames := make(map[string]struct{}, len(c.Policies))
	for i, policy := range c.Policies {
		if strings.TrimSpace(policy.Name) == "" {
			return fmt.Errorf("policies[%d].name is required", i)
		}
		if _, exists := policyNames[policy.Name]; exists {
			return fmt.Errorf("policies[%d].name %q must be unique", i, policy.Name)
		}
		policyNames[policy.Name] = struct{}{}
		switch NormalizeEnforcementMode(policy.Enforcement) {
		case EnforcementEnforce, EnforcementAudit:
		default:
			return fmt.Errorf("policies[%d].enforcement must be audit or enforce", i)
		}
		if policy.LegacyIdentitySelector != nil {
			return fmt.Errorf("policies[%d].identitySelector is no longer supported; use subjects instead", i)
		}
		hasKubernetesSubjects := policy.Subjects.Kubernetes != nil && len(policy.Subjects.Kubernetes.DiscoveryNames) > 0
		hasEC2Subjects := policy.Subjects.EC2 != nil && len(policy.Subjects.EC2.DiscoveryNames) > 0
		hasCIDRSubjects := len(policy.Subjects.CIDRs) > 0
		if !hasKubernetesSubjects && !hasEC2Subjects && !hasCIDRSubjects {
			return fmt.Errorf("policies[%d].subjects must reference at least one discovery provider or CIDR", i)
		}
		if policy.Subjects.Kubernetes != nil {
			if len(policy.Subjects.Kubernetes.DiscoveryNames) == 0 {
				return fmt.Errorf("policies[%d].subjects.kubernetes.discoveryNames must contain at least one discovery name", i)
			}
			if len(policy.Subjects.Kubernetes.Namespaces) == 0 {
				return fmt.Errorf("policies[%d].subjects.kubernetes.namespaces must contain at least one namespace", i)
			}
			for j, discoveryName := range policy.Subjects.Kubernetes.DiscoveryNames {
				if strings.TrimSpace(discoveryName) == "" {
					return fmt.Errorf("policies[%d].subjects.kubernetes.discoveryNames[%d] must not be empty", i, j)
				}
			}
			for j, namespace := range policy.Subjects.Kubernetes.Namespaces {
				if strings.TrimSpace(namespace) == "" {
					return fmt.Errorf("policies[%d].subjects.kubernetes.namespaces[%d] must not be empty", i, j)
				}
			}
		}
		if policy.Subjects.EC2 != nil {
			if len(policy.Subjects.EC2.DiscoveryNames) == 0 {
				return fmt.Errorf("policies[%d].subjects.ec2.discoveryNames must contain at least one discovery name", i)
			}
			for j, discoveryName := range policy.Subjects.EC2.DiscoveryNames {
				if strings.TrimSpace(discoveryName) == "" {
					return fmt.Errorf("policies[%d].subjects.ec2.discoveryNames[%d] must not be empty", i, j)
				}
			}
		}
		for j, cidr := range policy.Subjects.CIDRs {
			if cidr == "" {
				return fmt.Errorf("policies[%d].subjects.cidrs[%d] must not be empty", i, j)
			}
		}
		for j, rule := range policy.Egress {
			if strings.TrimSpace(rule.FQDN) == "" {
				return fmt.Errorf("policies[%d].egress[%d].fqdn is required", i, j)
			}
			if len(rule.Ports) == 0 {
				return fmt.Errorf("policies[%d].egress[%d].ports must contain at least one port", i, j)
			}
			for k, port := range rule.Ports {
				if port < 1 || port > 65535 {
					return fmt.Errorf("policies[%d].egress[%d].ports[%d] must be between 1 and 65535", i, j, k)
				}
			}
			switch rule.TLS.Mode {
			case "mitm", "passthrough":
			default:
				return fmt.Errorf("policies[%d].egress[%d].tls.mode must be mitm or passthrough", i, j)
			}
			if rule.TLS.Mode == "passthrough" && rule.HTTP != nil {
				return fmt.Errorf("policies[%d].egress[%d].http is only valid when tls.mode is mitm", i, j)
			}
			if rule.HTTP != nil {
				for k, method := range rule.HTTP.AllowedMethods {
					if strings.TrimSpace(method) == "" {
						return fmt.Errorf("policies[%d].egress[%d].http.allowedMethods[%d] must not be empty", i, j, k)
					}
				}
				for k, path := range rule.HTTP.AllowedPaths {
					if strings.TrimSpace(path) == "" {
						return fmt.Errorf("policies[%d].egress[%d].http.allowedPaths[%d] must not be empty", i, j, k)
					}
				}
			}
		}
	}
	discoveryNames := make(map[string]struct{}, len(c.Discovery.Kubernetes)+len(c.Discovery.EC2))
	kubernetesDiscoveryNames := make(map[string]struct{}, len(c.Discovery.Kubernetes))
	ec2DiscoveryNames := make(map[string]struct{}, len(c.Discovery.EC2))
	policyDiscoveryNames := make(map[string]struct{}, len(c.Discovery.Policies))
	for i, discovery := range c.Discovery.Kubernetes {
		discoveryName := normalizeDiscoveryBindingName(discovery.Name)
		if discoveryName == "" {
			return fmt.Errorf("discovery.kubernetes[%d].name is required", i)
		}
		if _, exists := discoveryNames[discoveryName]; exists {
			return fmt.Errorf("discovery.kubernetes[%d].name %q must be unique across discovery providers", i, discoveryName)
		}
		discoveryNames[discoveryName] = struct{}{}
		kubernetesDiscoveryNames[discoveryName] = struct{}{}
		if discovery.LegacyKubeconfig.Set {
			return fmt.Errorf("discovery.kubernetes[%d].kubeconfig is no longer supported; use auth.provider: kubeconfig and auth.kubeconfig", i)
		}
		switch normalizeKubernetesAuthProvider(discovery.Auth.Provider) {
		case "kubeconfig":
			if strings.TrimSpace(discovery.Auth.Kubeconfig) == "" {
				return fmt.Errorf("discovery.kubernetes[%d].auth.kubeconfig is required for kubeconfig auth", i)
			}
		case "incluster":
		case "eks":
			if strings.TrimSpace(discovery.Auth.Region) == "" || strings.TrimSpace(discovery.Auth.ClusterName) == "" {
				return fmt.Errorf("discovery.kubernetes[%d].auth.region and clusterName are required for eks auth", i)
			}
		case "gke":
			if strings.TrimSpace(discovery.Auth.Project) == "" || strings.TrimSpace(discovery.Auth.Location) == "" || strings.TrimSpace(discovery.Auth.ClusterName) == "" {
				return fmt.Errorf("discovery.kubernetes[%d].auth.project, location, and clusterName are required for gke auth", i)
			}
		case "aks":
			if strings.TrimSpace(discovery.Auth.SubscriptionID) == "" || strings.TrimSpace(discovery.Auth.ResourceGroup) == "" || strings.TrimSpace(discovery.Auth.ClusterName) == "" {
				return fmt.Errorf("discovery.kubernetes[%d].auth.subscriptionID, resourceGroup, and clusterName are required for aks auth", i)
			}
		default:
			return fmt.Errorf("discovery.kubernetes[%d].auth.provider must be kubeconfig, inCluster, eks, gke, or aks", i)
		}
		for j, namespace := range discovery.Namespaces {
			if strings.TrimSpace(namespace) == "" {
				return fmt.Errorf("discovery.kubernetes[%d].namespaces[%d] must not be empty", i, j)
			}
		}
		if discovery.ResyncPeriod != nil && *discovery.ResyncPeriod <= 0 {
			return fmt.Errorf("discovery.kubernetes[%d].resyncPeriod must be greater than zero", i)
		}
	}
	for i, discovery := range c.Discovery.EC2 {
		discoveryName := normalizeDiscoveryBindingName(discovery.Name)
		if discoveryName == "" {
			return fmt.Errorf("discovery.ec2[%d].name is required", i)
		}
		if _, exists := discoveryNames[discoveryName]; exists {
			return fmt.Errorf("discovery.ec2[%d].name %q must be unique across discovery providers", i, discoveryName)
		}
		discoveryNames[discoveryName] = struct{}{}
		ec2DiscoveryNames[discoveryName] = struct{}{}
		if strings.TrimSpace(discovery.Region) == "" {
			return fmt.Errorf("discovery.ec2[%d].region is required", i)
		}
		for j, filter := range discovery.TagFilters {
			if strings.TrimSpace(filter.Key) == "" {
				return fmt.Errorf("discovery.ec2[%d].tagFilters[%d].key is required", i, j)
			}
			for k, value := range filter.Values {
				if strings.TrimSpace(value) == "" {
					return fmt.Errorf("discovery.ec2[%d].tagFilters[%d].values[%d] must not be empty", i, j, k)
				}
			}
		}
		if discovery.PollInterval != nil && *discovery.PollInterval <= 0 {
			return fmt.Errorf("discovery.ec2[%d].pollInterval must be greater than zero", i)
		}
	}
	for i, discovery := range c.Discovery.Policies {
		discoveryName := normalizeDiscoveryBindingName(discovery.Name)
		if discoveryName == "" {
			return fmt.Errorf("discovery.policies[%d].name is required", i)
		}
		if _, exists := policyDiscoveryNames[discoveryName]; exists {
			return fmt.Errorf("discovery.policies[%d].name %q must be unique", i, discoveryName)
		}
		policyDiscoveryNames[discoveryName] = struct{}{}
		switch normalizePolicyDiscoveryProvider(discovery.Provider) {
		case "aws", "gcp", "azure":
		default:
			return fmt.Errorf("discovery.policies[%d].provider must be aws, gcp, or azure", i)
		}
		if strings.TrimSpace(discovery.Bucket) == "" {
			return fmt.Errorf("discovery.policies[%d].bucket is required", i)
		}
		if discovery.PollInterval != nil && *discovery.PollInterval <= 0 {
			return fmt.Errorf("discovery.policies[%d].pollInterval must be greater than zero", i)
		}
		switch normalizePolicyDiscoveryAuthMode(discovery.Auth.Mode) {
		case "default":
		default:
			return fmt.Errorf("discovery.policies[%d].auth.mode must be default", i)
		}
	}
	for i, policy := range c.Policies {
		if policy.Subjects.Kubernetes != nil {
			for j, discoveryName := range policy.Subjects.Kubernetes.DiscoveryNames {
				normalizedDiscoveryName := normalizeDiscoveryBindingName(discoveryName)
				if _, exists := kubernetesDiscoveryNames[normalizedDiscoveryName]; !exists {
					return fmt.Errorf("policies[%d].subjects.kubernetes.discoveryNames[%d] references unknown kubernetes discovery %q", i, j, normalizedDiscoveryName)
				}
			}
		}
		if policy.Subjects.EC2 != nil {
			for j, discoveryName := range policy.Subjects.EC2.DiscoveryNames {
				normalizedDiscoveryName := normalizeDiscoveryBindingName(discoveryName)
				if _, exists := ec2DiscoveryNames[normalizedDiscoveryName]; !exists {
					return fmt.Errorf("policies[%d].subjects.ec2.discoveryNames[%d] references unknown ec2 discovery %q", i, j, normalizedDiscoveryName)
				}
			}
		}
	}

	return nil
}

func NormalizeEnforcementMode(mode string) string {
	if strings.TrimSpace(mode) == "" {
		return EnforcementEnforce
	}
	return strings.ToLower(strings.TrimSpace(mode))
}

func NormalizeUnknownIdentityPolicy(policy string) string {
	if strings.TrimSpace(policy) == "" {
		return UnknownIdentityAllow
	}
	return strings.ToLower(strings.TrimSpace(policy))
}

func normalizeKubernetesAuthProvider(provider string) string {
	return strings.ToLower(strings.TrimSpace(provider))
}

func normalizePolicyDiscoveryProvider(provider string) string {
	return strings.ToLower(strings.TrimSpace(provider))
}

func normalizePolicyDiscoveryAuthMode(mode string) string {
	if strings.TrimSpace(mode) == "" {
		return "default"
	}
	return strings.ToLower(strings.TrimSpace(mode))
}

func normalizeDiscoveryBindingName(name string) string {
	return strings.TrimSpace(name)
}

func (c *Config) normalizeDiscoveryBindings() error {
	for i := range c.Discovery.Kubernetes {
		c.Discovery.Kubernetes[i].Name = normalizeDiscoveryBindingName(c.Discovery.Kubernetes[i].Name)
	}
	for i := range c.Discovery.EC2 {
		c.Discovery.EC2[i].Name = normalizeDiscoveryBindingName(c.Discovery.EC2[i].Name)
	}
	for i := range c.Discovery.Policies {
		c.Discovery.Policies[i].Name = normalizeDiscoveryBindingName(c.Discovery.Policies[i].Name)
		c.Discovery.Policies[i].Provider = normalizePolicyDiscoveryProvider(c.Discovery.Policies[i].Provider)
		c.Discovery.Policies[i].Auth.Mode = normalizePolicyDiscoveryAuthMode(c.Discovery.Policies[i].Auth.Mode)
	}
	for i := range c.Policies {
		if c.Policies[i].Subjects.Kubernetes != nil {
			for j := range c.Policies[i].Subjects.Kubernetes.DiscoveryNames {
				c.Policies[i].Subjects.Kubernetes.DiscoveryNames[j] = normalizeDiscoveryBindingName(c.Policies[i].Subjects.Kubernetes.DiscoveryNames[j])
			}
		}
		if c.Policies[i].Subjects.EC2 != nil {
			for j := range c.Policies[i].Subjects.EC2.DiscoveryNames {
				c.Policies[i].Subjects.EC2.DiscoveryNames[j] = normalizeDiscoveryBindingName(c.Policies[i].Subjects.EC2.DiscoveryNames[j])
			}
		}
		for j := range c.Policies[i].Subjects.CIDRs {
			normalizedCIDR, err := normalizeCIDRSubject(c.Policies[i].Subjects.CIDRs[j])
			if err != nil {
				return fmt.Errorf("policies[%d].subjects.cidrs[%d] must be a valid CIDR: %w", i, j, err)
			}
			c.Policies[i].Subjects.CIDRs[j] = normalizedCIDR
		}
	}

	return nil
}

func (c *Config) hydrateCompatibilityFields() {
	for i := range c.Discovery.Kubernetes {
		if c.Discovery.Kubernetes[i].Kubeconfig == "" && normalizeKubernetesAuthProvider(c.Discovery.Kubernetes[i].Auth.Provider) == "kubeconfig" {
			c.Discovery.Kubernetes[i].Kubeconfig = c.Discovery.Kubernetes[i].Auth.Kubeconfig
		}
	}
	for i := range c.Policies {
		if len(c.Policies[i].IdentitySelector.MatchLabels) == 0 && c.Policies[i].Subjects.Kubernetes != nil {
			c.Policies[i].IdentitySelector.MatchLabels = cloneStringMap(c.Policies[i].Subjects.Kubernetes.MatchLabels)
		}
	}
}

func cloneStringMap(src map[string]string) map[string]string {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[string]string, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func normalizeCIDRSubject(value string) (string, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "", fmt.Errorf("must not be empty")
	}
	prefix, err := netip.ParsePrefix(trimmed)
	if err != nil {
		return "", err
	}
	return prefix.Masked().String(), nil
}

func validateLocalhostListen(addr string) error {
	host, _, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return err
	}
	switch host {
	case "127.0.0.1", "::1", "localhost":
		return nil
	default:
		return fmt.Errorf("host %q is not loopback", host)
	}
}

func listenersConflict(a string, b string) bool {
	aHost, aPort, err := splitListenAddress(a)
	if err != nil {
		return a == b
	}
	bHost, bPort, err := splitListenAddress(b)
	if err != nil {
		return a == b
	}
	if aPort != bPort {
		return false
	}
	if isWildcardListenHost(aHost) || isWildcardListenHost(bHost) {
		return true
	}
	return sameListenHost(aHost, bHost)
}

func splitListenAddress(addr string) (string, string, error) {
	host, port, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return "", "", err
	}
	return strings.TrimSpace(host), strings.TrimSpace(port), nil
}

func isWildcardListenHost(host string) bool {
	switch strings.TrimSpace(host) {
	case "", "0.0.0.0", "::":
		return true
	default:
		return false
	}
}

func sameListenHost(a string, b string) bool {
	a = strings.TrimSpace(a)
	b = strings.TrimSpace(b)
	if a == b {
		return true
	}
	if a == "localhost" && isLoopbackListenHost(b) {
		return true
	}
	if b == "localhost" && isLoopbackListenHost(a) {
		return true
	}
	return false
}

func isLoopbackListenHost(host string) bool {
	switch strings.TrimSpace(host) {
	case "127.0.0.1", "::1":
		return true
	default:
		return false
	}
}
