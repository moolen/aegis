package config

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	defaultMetricsListen = ":9090"
	defaultDNSCacheTTL   = 30 * time.Second
	defaultDNSTimeout    = 5 * time.Second
)

type Config struct {
	Proxy     ProxyConfig     `yaml:"proxy"`
	Metrics   MetricsConfig   `yaml:"metrics"`
	DNS       DNSConfig       `yaml:"dns"`
	Policies  []PolicyConfig  `yaml:"policies"`
	Discovery DiscoveryConfig `yaml:"discovery"`
}

type ProxyConfig struct {
	Listen string `yaml:"listen"`
}

type MetricsConfig struct {
	Listen string `yaml:"listen"`
}

type DNSConfig struct {
	CacheTTL time.Duration `yaml:"cache_ttl"`
	Timeout  time.Duration `yaml:"timeout"`
	Servers  []string      `yaml:"servers"`
}

type DiscoveryConfig struct {
	Kubernetes []KubernetesDiscoveryConfig `yaml:"kubernetes"`
}

type KubernetesDiscoveryConfig struct {
	Name         string         `yaml:"name"`
	Kubeconfig   string         `yaml:"kubeconfig"`
	Namespaces   []string       `yaml:"namespaces"`
	ResyncPeriod *time.Duration `yaml:"resyncPeriod"`
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
		Metrics: MetricsConfig{Listen: defaultMetricsListen},
		DNS: DNSConfig{
			CacheTTL: defaultDNSCacheTTL,
			Timeout:  defaultDNSTimeout,
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
	if c.Metrics.Listen == "" {
		return fmt.Errorf("metrics.listen is required")
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

	return nil
}
