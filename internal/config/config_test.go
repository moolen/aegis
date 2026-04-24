package config

import (
	"bytes"
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
