package config

import (
	"fmt"
	"io"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	defaultMetricsListen = ":9090"
	defaultDNSCacheTTL   = 30 * time.Second
	defaultDNSTimeout    = 5 * time.Second
)

type Config struct {
	Proxy   ProxyConfig   `yaml:"proxy"`
	Metrics MetricsConfig `yaml:"metrics"`
	DNS     DNSConfig     `yaml:"dns"`
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

	return nil
}
