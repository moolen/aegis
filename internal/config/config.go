package config

import (
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	defaultMetricsListen = ":9090"
	defaultDNSCacheTTL   = 30 * time.Second
	defaultDNSTimeout    = 5 * time.Second
	defaultGracePeriod   = 10 * time.Second
	EnforcementEnforce   = "enforce"
	EnforcementAudit     = "audit"
)

type Config struct {
	Proxy     ProxyConfig     `yaml:"proxy"`
	Metrics   MetricsConfig   `yaml:"metrics"`
	DNS       DNSConfig       `yaml:"dns"`
	Shutdown  ShutdownConfig  `yaml:"shutdown"`
	Policies  []PolicyConfig  `yaml:"policies"`
	Discovery DiscoveryConfig `yaml:"discovery"`
}

type ProxyConfig struct {
	Enforcement   string              `yaml:"enforcement"`
	Listen        string              `yaml:"listen"`
	CA            CAConfig            `yaml:"ca"`
	ProxyProtocol ProxyProtocolConfig `yaml:"proxyProtocol"`
}

type CAConfig struct {
	CertFile string `yaml:"certFile"`
	KeyFile  string `yaml:"keyFile"`
}

type ProxyProtocolConfig struct {
	Enabled       bool           `yaml:"enabled"`
	HeaderTimeout *time.Duration `yaml:"headerTimeout"`
}

type MetricsConfig struct {
	Listen string `yaml:"listen"`
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
	Kubernetes []KubernetesDiscoveryConfig `yaml:"kubernetes"`
	EC2        []EC2DiscoveryConfig        `yaml:"ec2"`
}

type KubernetesDiscoveryConfig struct {
	Name         string         `yaml:"name"`
	Kubeconfig   string         `yaml:"kubeconfig"`
	Namespaces   []string       `yaml:"namespaces"`
	ResyncPeriod *time.Duration `yaml:"resyncPeriod"`
}

type EC2DiscoveryConfig struct {
	Name         string               `yaml:"name"`
	Region       string               `yaml:"region"`
	TagFilters   []EC2TagFilterConfig `yaml:"tagFilters"`
	PollInterval *time.Duration       `yaml:"pollInterval"`
}

type EC2TagFilterConfig struct {
	Key    string   `yaml:"key"`
	Values []string `yaml:"values"`
}

type PolicyConfig struct {
	Name             string                 `yaml:"name"`
	IdentitySelector IdentitySelectorConfig `yaml:"identitySelector"`
	Egress           []EgressRuleConfig     `yaml:"egress"`
}

type IdentitySelectorConfig struct {
	MatchLabels map[string]string `yaml:"matchLabels"`
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
			Enforcement: EnforcementEnforce,
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

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}

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
	if (c.Proxy.CA.CertFile == "") != (c.Proxy.CA.KeyFile == "") {
		return fmt.Errorf("proxy.ca.certFile and proxy.ca.keyFile must be set together")
	}
	if c.Proxy.ProxyProtocol.HeaderTimeout != nil && *c.Proxy.ProxyProtocol.HeaderTimeout <= 0 {
		return fmt.Errorf("proxy.proxyProtocol.headerTimeout must be greater than zero")
	}
	if c.Metrics.Listen == "" {
		return fmt.Errorf("metrics.listen is required")
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
	for i, policy := range c.Policies {
		if strings.TrimSpace(policy.Name) == "" {
			return fmt.Errorf("policies[%d].name is required", i)
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
	for i, discovery := range c.Discovery.Kubernetes {
		if strings.TrimSpace(discovery.Name) == "" {
			return fmt.Errorf("discovery.kubernetes[%d].name is required", i)
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
		if strings.TrimSpace(discovery.Name) == "" {
			return fmt.Errorf("discovery.ec2[%d].name is required", i)
		}
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

	return nil
}

func NormalizeEnforcementMode(mode string) string {
	if strings.TrimSpace(mode) == "" {
		return EnforcementEnforce
	}
	return strings.ToLower(strings.TrimSpace(mode))
}
