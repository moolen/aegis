package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/moolen/aegis/internal/config"
	"github.com/moolen/aegis/internal/identity"
	appmetrics "github.com/moolen/aegis/internal/metrics"
	"github.com/moolen/aegis/internal/policy"
	"github.com/moolen/aegis/internal/policydiscovery"
	"github.com/moolen/aegis/internal/proxy"
)

func runtimeTestKubernetesSubjects() config.PolicySubjectsConfig {
	return config.PolicySubjectsConfig{
		Kubernetes: &config.KubernetesSubjectConfig{
			DiscoveryNames: []string{"cluster-a"},
			Namespaces:     []string{"default"},
			MatchLabels: map[string]string{
				"app": "web",
			},
		},
	}
}

func runtimeTestKubernetesDiscovery() config.DiscoveryConfig {
	return config.DiscoveryConfig{
		Kubernetes: []config.KubernetesDiscoveryConfig{{
			Name: "cluster-a",
			Auth: config.KubernetesAuthConfig{
				Provider: "inCluster",
			},
		}},
	}
}

func stubRuntimeKubernetesProvider(t *testing.T) {
	t.Helper()

	restoreProvider := newKubernetesRuntimeProvider
	t.Cleanup(func() {
		newKubernetesRuntimeProvider = restoreProvider
	})

	newKubernetesRuntimeProvider = func(cfg config.KubernetesDiscoveryConfig, logger *slog.Logger) (identity.RuntimeProvider, error) {
		return identity.RuntimeProvider{
			Name: cfg.Name,
			Kind: "kubernetes",
			Provider: fakeStartableResolver{
				identity: &identity.Identity{
					Source:   "kubernetes",
					Provider: cfg.Name,
					Name:     "default/web",
					Labels: map[string]string{
						"kubernetes.io/namespace": "default",
						"app":                     "web",
					},
				},
			},
		}, nil
	}
}

func TestBuildIdentityResolverKeepsHealthyProvidersAfterStartupFailure(t *testing.T) {
	restoreKubernetes := newKubernetesRuntimeProvider
	restoreEC2 := newEC2RuntimeProvider
	t.Cleanup(func() {
		newKubernetesRuntimeProvider = restoreKubernetes
		newEC2RuntimeProvider = restoreEC2
	})
	newEC2RuntimeProvider = func(cfg config.EC2DiscoveryConfig, logger *slog.Logger) (identity.RuntimeProvider, error) {
		t.Fatalf("unexpected ec2 provider build for %q", cfg.Name)
		return identity.RuntimeProvider{}, nil
	}

	var attempts []string
	newKubernetesRuntimeProvider = func(cfg config.KubernetesDiscoveryConfig, logger *slog.Logger) (identity.RuntimeProvider, error) {
		attempts = append(attempts, cfg.Name)
		switch cfg.Name {
		case "broken-a":
			return identity.RuntimeProvider{}, errors.New("bad kubeconfig")
		case "cluster-b":
			return identity.RuntimeProvider{
				Name: "cluster-b",
				Kind: "kubernetes",
				Provider: fakeStartableResolver{
					identity: &identity.Identity{Name: "ns-b/api"},
				},
			}, nil
		default:
			t.Fatalf("unexpected provider %q", cfg.Name)
			return identity.RuntimeProvider{}, nil
		}
	}

	reg := prometheus.NewRegistry()
	m := appmetrics.New(reg)
	resolver, err := buildIdentityResolver(context.Background(), config.DiscoveryConfig{
		Kubernetes: []config.KubernetesDiscoveryConfig{
			{Name: "broken-a"},
			{Name: "cluster-b"},
		},
	}, slog.New(slog.NewTextHandler(io.Discard, nil)), m)
	if err != nil {
		t.Fatalf("buildIdentityResolver() error = %v", err)
	}
	if len(attempts) != 2 {
		t.Fatalf("attempts = %#v, want broken-a then cluster-b", attempts)
	}
	id, err := resolver.Resolve(net.ParseIP("10.0.0.10"))
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if id == nil || id.Name != "ns-b/api" {
		t.Fatalf("Resolve() identity = %#v, want ns-b/api", id)
	}
	if got := counterValue(t, reg, "aegis_discovery_provider_failures_total", map[string]string{"provider": "broken-a", "kind": "kubernetes", "stage": "build"}); got != 1 {
		t.Fatalf("build failure metric = %v, want 1", got)
	}
	if metricExists(reg, "aegis_discovery_provider_starts_total", map[string]string{"provider": "broken-a", "kind": "kubernetes"}) {
		t.Fatal("broken-a build failure unexpectedly counted as a provider start")
	}
	if got := counterValue(t, reg, "aegis_discovery_provider_starts_total", map[string]string{"provider": "cluster-b", "kind": "kubernetes"}); got != 1 {
		t.Fatalf("start counter = %v, want 1", got)
	}
	if got := gaugeValue(t, reg, "aegis_discovery_providers_active"); got != 1 {
		t.Fatalf("active provider gauge = %v, want 1", got)
	}
}

func TestBuildUpstreamTLSConfigLoadsSSLCertFile(t *testing.T) {
	caPEM, _ := generateTestCA(t)

	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "roots.pem")
	if err := os.WriteFile(certFile, caPEM, 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	previous := os.Getenv("SSL_CERT_FILE")
	if err := os.Setenv("SSL_CERT_FILE", certFile); err != nil {
		t.Fatalf("Setenv() error = %v", err)
	}
	t.Cleanup(func() {
		if previous == "" {
			_ = os.Unsetenv("SSL_CERT_FILE")
			return
		}
		_ = os.Setenv("SSL_CERT_FILE", previous)
	})

	cfg, err := buildUpstreamTLSConfig()
	if err != nil {
		t.Fatalf("buildUpstreamTLSConfig() error = %v", err)
	}
	if cfg == nil || cfg.RootCAs == nil {
		t.Fatal("expected upstream TLS config with root CAs")
	}
	if got := len(cfg.RootCAs.Subjects()); got == 0 {
		t.Fatal("expected SSL_CERT_FILE roots to be loaded")
	}
}

func TestBuildIdentityResolverKeepsHealthyProvidersAfterStartupTimeout(t *testing.T) {
	restoreProvider := newKubernetesRuntimeProvider
	restoreTimeout := discoveryProviderStartupTimeout
	t.Cleanup(func() {
		newKubernetesRuntimeProvider = restoreProvider
		discoveryProviderStartupTimeout = restoreTimeout
	})

	discoveryProviderStartupTimeout = 20 * time.Millisecond

	newKubernetesRuntimeProvider = func(cfg config.KubernetesDiscoveryConfig, logger *slog.Logger) (identity.RuntimeProvider, error) {
		switch cfg.Name {
		case "stuck-a":
			return identity.RuntimeProvider{
				Name: "stuck-a",
				Kind: "kubernetes",
				Provider: fakeStartableResolver{
					startFn: func(ctx context.Context, startupTimeout time.Duration) error {
						select {
						case <-ctx.Done():
							return ctx.Err()
						case <-time.After(startupTimeout):
							return context.DeadlineExceeded
						}
					},
				},
			}, nil
		case "cluster-b":
			return identity.RuntimeProvider{
				Name: "cluster-b",
				Kind: "kubernetes",
				Provider: fakeStartableResolver{
					identity: &identity.Identity{Name: "ns-b/api"},
				},
			}, nil
		default:
			t.Fatalf("unexpected provider %q", cfg.Name)
			return identity.RuntimeProvider{}, nil
		}
	}

	reg := prometheus.NewRegistry()
	m := appmetrics.New(reg)

	start := time.Now()
	resolver, err := buildIdentityResolver(context.Background(), config.DiscoveryConfig{
		Kubernetes: []config.KubernetesDiscoveryConfig{
			{Name: "stuck-a"},
			{Name: "cluster-b"},
		},
	}, slog.New(slog.NewTextHandler(io.Discard, nil)), m)
	if err != nil {
		t.Fatalf("buildIdentityResolver() error = %v", err)
	}
	if elapsed := time.Since(start); elapsed > 250*time.Millisecond {
		t.Fatalf("buildIdentityResolver() took %s, want timeout-bounded startup", elapsed)
	}

	id, err := resolver.Resolve(net.ParseIP("10.0.0.10"))
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if id == nil || id.Name != "ns-b/api" {
		t.Fatalf("Resolve() identity = %#v, want ns-b/api", id)
	}
	if got := counterValue(t, reg, "aegis_discovery_provider_failures_total", map[string]string{"provider": "stuck-a", "kind": "kubernetes", "stage": "start"}); got != 1 {
		t.Fatalf("start failure metric = %v, want 1", got)
	}
	if got := counterValue(t, reg, "aegis_discovery_provider_starts_total", map[string]string{"provider": "stuck-a", "kind": "kubernetes"}); got != 1 {
		t.Fatalf("start counter = %v, want 1", got)
	}
	if got := counterValue(t, reg, "aegis_discovery_provider_starts_total", map[string]string{"provider": "cluster-b", "kind": "kubernetes"}); got != 1 {
		t.Fatalf("healthy provider start counter = %v, want 1", got)
	}
}

func TestBuildIdentityResolverFailsWhenDiscoveryConfiguredButNoProviderIsHealthy(t *testing.T) {
	restoreKubernetes := newKubernetesRuntimeProvider
	restoreEC2 := newEC2RuntimeProvider
	t.Cleanup(func() {
		newKubernetesRuntimeProvider = restoreKubernetes
		newEC2RuntimeProvider = restoreEC2
	})
	newEC2RuntimeProvider = func(cfg config.EC2DiscoveryConfig, logger *slog.Logger) (identity.RuntimeProvider, error) {
		t.Fatalf("unexpected ec2 provider build for %q", cfg.Name)
		return identity.RuntimeProvider{}, nil
	}

	newKubernetesRuntimeProvider = func(cfg config.KubernetesDiscoveryConfig, logger *slog.Logger) (identity.RuntimeProvider, error) {
		if cfg.Name == "broken-a" {
			return identity.RuntimeProvider{}, errors.New("bad kubeconfig")
		}
		return identity.RuntimeProvider{
			Name:     "cluster-b",
			Kind:     "kubernetes",
			Provider: fakeStartableResolver{startErr: errors.New("sync failed")},
		}, nil
	}

	reg := prometheus.NewRegistry()
	m := appmetrics.New(reg)
	_, err := buildIdentityResolver(context.Background(), config.DiscoveryConfig{
		Kubernetes: []config.KubernetesDiscoveryConfig{
			{Name: "broken-a"},
			{Name: "cluster-b"},
		},
	}, slog.New(slog.NewTextHandler(io.Discard, nil)), m)
	if err == nil {
		t.Fatal("expected startup failure")
	}
	if got := counterValue(t, reg, "aegis_discovery_provider_failures_total", map[string]string{"provider": "cluster-b", "kind": "kubernetes", "stage": "start"}); got != 1 {
		t.Fatalf("start failure metric = %v, want 1", got)
	}
}

func TestBuildIdentityResolverReturnsNilWhenDiscoveryDisabled(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := appmetrics.New(reg)
	resolver, err := buildIdentityResolver(context.Background(), config.DiscoveryConfig{}, slog.New(slog.NewTextHandler(io.Discard, nil)), m)
	if err != nil {
		t.Fatalf("buildIdentityResolver() error = %v", err)
	}
	if resolver != nil {
		t.Fatalf("resolver = %#v, want nil", resolver)
	}
}

func TestBuildServersInjectsIdentityResolverIntoProxy(t *testing.T) {
	restoreProvider := newKubernetesRuntimeProvider
	restoreEC2Provider := newEC2RuntimeProvider
	restoreMITMEngine := newMITMEngineFromFiles
	restoreProxyServer := newProxyServer
	t.Cleanup(func() {
		newKubernetesRuntimeProvider = restoreProvider
		newEC2RuntimeProvider = restoreEC2Provider
		newMITMEngineFromFiles = restoreMITMEngine
		newProxyServer = restoreProxyServer
	})

	newKubernetesRuntimeProvider = func(cfg config.KubernetesDiscoveryConfig, logger *slog.Logger) (identity.RuntimeProvider, error) {
		if cfg.Name != "cluster-a" {
			t.Fatalf("unexpected provider %q", cfg.Name)
		}
		return identity.RuntimeProvider{
			Name: "cluster-a",
			Kind: "kubernetes",
			Provider: fakeStartableResolver{
				identity: &identity.Identity{Name: "default/api"},
			},
		}, nil
	}
	newEC2RuntimeProvider = func(cfg config.EC2DiscoveryConfig, logger *slog.Logger) (identity.RuntimeProvider, error) {
		t.Fatalf("unexpected ec2 provider build for %q", cfg.Name)
		return identity.RuntimeProvider{}, nil
	}

	var captured proxy.Dependencies
	newProxyServer = func(deps proxy.Dependencies) interface{ Handler() http.Handler } {
		captured = deps
		return fakeHandlerProvider{handler: http.NewServeMux()}
	}

	_, _, _, _, _, err := buildServers(context.Background(), config.Config{
		Proxy:   config.ProxyConfig{Listen: ":8080"},
		Metrics: config.MetricsConfig{Listen: ":9090"},
		Policies: []config.PolicyConfig{{
			Name:     "allow-example",
			Subjects: runtimeTestKubernetesSubjects(),
			Egress: []config.EgressRuleConfig{{
				FQDN:  "example.com",
				Ports: []int{443},
				TLS:   config.TLSRuleConfig{Mode: "passthrough"},
			}},
		}},
		Discovery: runtimeTestKubernetesDiscovery(),
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("buildServers() error = %v", err)
	}
	if captured.IdentityResolver == nil {
		t.Fatal("IdentityResolver was not injected into proxy dependencies")
	}

	id, err := captured.IdentityResolver.Resolve(net.ParseIP("10.0.0.10"))
	if err != nil {
		t.Fatalf("IdentityResolver.Resolve() error = %v", err)
	}
	if id == nil || id.Name != "default/api" {
		t.Fatalf("IdentityResolver.Resolve() identity = %#v, want default/api", id)
	}
}

func TestBuildServersCreatesAdminServerOnlyWhenEnabled(t *testing.T) {
	stubRuntimeKubernetesProvider(t)

	_, _, adminSrv, _, _, err := buildServers(context.Background(), config.Config{
		Proxy:   config.ProxyConfig{Listen: ":8080"},
		Metrics: config.MetricsConfig{Listen: ":9090"},
		Admin: config.AdminConfig{
			Enabled: true,
			Listen:  "127.0.0.1:9091",
			Token:   "secret-token",
		},
		Policies: []config.PolicyConfig{{
			Name:     "allow-example",
			Subjects: runtimeTestKubernetesSubjects(),
			Egress: []config.EgressRuleConfig{{
				FQDN:  "example.com",
				Ports: []int{443},
				TLS:   config.TLSRuleConfig{Mode: "passthrough"},
			}},
		}},
		Discovery: runtimeTestKubernetesDiscovery(),
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("buildServers() error = %v", err)
	}
	if adminSrv == nil {
		t.Fatal("expected admin server when admin is enabled")
	}

	_, _, adminSrv, _, _, err = buildServers(context.Background(), config.Config{
		Proxy:   config.ProxyConfig{Listen: ":8080"},
		Metrics: config.MetricsConfig{Listen: ":9090"},
		Policies: []config.PolicyConfig{{
			Name:     "allow-example",
			Subjects: runtimeTestKubernetesSubjects(),
			Egress: []config.EgressRuleConfig{{
				FQDN:  "example.com",
				Ports: []int{443},
				TLS:   config.TLSRuleConfig{Mode: "passthrough"},
			}},
		}},
		Discovery: runtimeTestKubernetesDiscovery(),
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("buildServers() error = %v", err)
	}
	if adminSrv != nil {
		t.Fatal("expected no admin server when admin is disabled")
	}
}

func TestBuildServersIncludesPprofWhenEnabled(t *testing.T) {
	stubRuntimeKubernetesProvider(t)

	_, _, _, pprofSrv, _, err := buildServers(context.Background(), config.Config{
		Proxy:   config.ProxyConfig{Listen: ":8080"},
		Metrics: config.MetricsConfig{Listen: ":9090"},
		Pprof: config.PprofConfig{
			Enabled: true,
			Listen:  "127.0.0.1:6060",
		},
		Policies: []config.PolicyConfig{{
			Name:     "allow-example",
			Subjects: runtimeTestKubernetesSubjects(),
			Egress: []config.EgressRuleConfig{{
				FQDN:  "example.com",
				Ports: []int{443},
				TLS:   config.TLSRuleConfig{Mode: "passthrough"},
			}},
		}},
		Discovery: runtimeTestKubernetesDiscovery(),
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("buildServers() error = %v", err)
	}
	if pprofSrv == nil {
		t.Fatal("expected pprof server when pprof is enabled")
	}
	if got := pprofSrv.Addr; got != "127.0.0.1:6060" {
		t.Fatalf("pprof server addr = %q, want %q", got, "127.0.0.1:6060")
	}
}

func TestBuildServersOmitsPprofWhenDisabled(t *testing.T) {
	stubRuntimeKubernetesProvider(t)

	_, _, _, pprofSrv, _, err := buildServers(context.Background(), config.Config{
		Proxy:   config.ProxyConfig{Listen: ":8080"},
		Metrics: config.MetricsConfig{Listen: ":9090"},
		Policies: []config.PolicyConfig{{
			Name:     "allow-example",
			Subjects: runtimeTestKubernetesSubjects(),
			Egress: []config.EgressRuleConfig{{
				FQDN:  "example.com",
				Ports: []int{443},
				TLS:   config.TLSRuleConfig{Mode: "passthrough"},
			}},
		}},
		Discovery: runtimeTestKubernetesDiscovery(),
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("buildServers() error = %v", err)
	}
	if pprofSrv != nil {
		t.Fatal("expected no pprof server when pprof is disabled")
	}
}

func TestBuildListenersCreatesPprofListenerWhenEnabled(t *testing.T) {
	cfg := config.Config{
		Proxy:   config.ProxyConfig{Listen: "127.0.0.1:0"},
		Metrics: config.MetricsConfig{Listen: "127.0.0.1:0"},
		Pprof: config.PprofConfig{
			Enabled: true,
			Listen:  "127.0.0.1:0",
		},
	}

	proxyListener, metricsListener, adminListener, pprofListener, err := buildListeners(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), appmetrics.New(prometheus.NewRegistry()))
	if err != nil {
		t.Fatalf("buildListeners() error = %v", err)
	}
	defer proxyListener.Close()
	defer metricsListener.Close()
	if adminListener != nil {
		t.Fatalf("expected no admin listener, got %v", adminListener.Addr())
	}
	if pprofListener == nil {
		t.Fatal("expected pprof listener when pprof is enabled")
	}
	defer pprofListener.Close()
}

func TestBuildServersInjectsMITMEngineIntoProxy(t *testing.T) {
	restoreKubernetesProvider := newKubernetesRuntimeProvider
	restoreEC2Provider := newEC2RuntimeProvider
	restoreMITMEngine := newMITMEngineFromFiles
	restoreProxyServer := newProxyServer
	t.Cleanup(func() {
		newKubernetesRuntimeProvider = restoreKubernetesProvider
		newEC2RuntimeProvider = restoreEC2Provider
		newMITMEngineFromFiles = restoreMITMEngine
		newProxyServer = restoreProxyServer
	})

	newKubernetesRuntimeProvider = func(cfg config.KubernetesDiscoveryConfig, logger *slog.Logger) (identity.RuntimeProvider, error) {
		return identity.RuntimeProvider{
			Name: cfg.Name,
			Kind: "kubernetes",
			Provider: fakeStartableResolver{
				identity: &identity.Identity{
					Source:   "kubernetes",
					Provider: cfg.Name,
					Name:     "default/web",
					Labels: map[string]string{
						"kubernetes.io/namespace": "default",
						"app":                     "web",
					},
				},
			},
		}, nil
	}
	newEC2RuntimeProvider = func(cfg config.EC2DiscoveryConfig, logger *slog.Logger) (identity.RuntimeProvider, error) {
		t.Fatalf("unexpected ec2 provider build for %q", cfg.Name)
		return identity.RuntimeProvider{}, nil
	}

	var gotCertFile string
	var gotKeyFile string
	expectedMITM := &proxy.MITMEngine{}
	newMITMEngineFromFiles = func(certFile string, keyFile string, logger *slog.Logger) (*proxy.MITMEngine, error) {
		gotCertFile = certFile
		gotKeyFile = keyFile
		return expectedMITM, nil
	}

	var captured proxy.Dependencies
	newProxyServer = func(deps proxy.Dependencies) interface{ Handler() http.Handler } {
		captured = deps
		return fakeHandlerProvider{handler: http.NewServeMux()}
	}

	_, _, _, _, _, err := buildServers(context.Background(), config.Config{
		Proxy: config.ProxyConfig{
			Listen: ":8080",
			CA: config.CAConfig{
				CertFile: "/tmp/aegis-ca.crt",
				KeyFile:  "/tmp/aegis-ca.key",
			},
		},
		Metrics: config.MetricsConfig{Listen: ":9090"},
		Policies: []config.PolicyConfig{{
			Name:     "allow-example",
			Subjects: runtimeTestKubernetesSubjects(),
			Egress: []config.EgressRuleConfig{{
				FQDN:  "example.com",
				Ports: []int{443},
				TLS:   config.TLSRuleConfig{Mode: "passthrough"},
			}},
		}},
		Discovery: runtimeTestKubernetesDiscovery(),
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("buildServers() error = %v", err)
	}

	if gotCertFile != "/tmp/aegis-ca.crt" || gotKeyFile != "/tmp/aegis-ca.key" {
		t.Fatalf("mitm engine files = (%q, %q), want (/tmp/aegis-ca.crt, /tmp/aegis-ca.key)", gotCertFile, gotKeyFile)
	}
	if captured.MITM != expectedMITM {
		t.Fatalf("captured MITM engine = %#v, want injected engine %#v", captured.MITM, expectedMITM)
	}
}

func TestBuildServersFailsWhenMITMEngineLoadFails(t *testing.T) {
	restoreKubernetesProvider := newKubernetesRuntimeProvider
	restoreMITMEngine := newMITMEngineFromFiles
	t.Cleanup(func() {
		newKubernetesRuntimeProvider = restoreKubernetesProvider
		newMITMEngineFromFiles = restoreMITMEngine
	})

	newKubernetesRuntimeProvider = func(cfg config.KubernetesDiscoveryConfig, logger *slog.Logger) (identity.RuntimeProvider, error) {
		return identity.RuntimeProvider{
			Name: cfg.Name,
			Kind: "kubernetes",
			Provider: fakeStartableResolver{
				identity: &identity.Identity{
					Source:   "kubernetes",
					Provider: cfg.Name,
					Name:     "default/web",
					Labels: map[string]string{
						"kubernetes.io/namespace": "default",
						"app":                     "web",
					},
				},
			},
		}, nil
	}
	newMITMEngineFromFiles = func(certFile string, keyFile string, logger *slog.Logger) (*proxy.MITMEngine, error) {
		return nil, errors.New("bad ca")
	}

	_, _, _, _, _, err := buildServers(context.Background(), config.Config{
		Proxy: config.ProxyConfig{
			Listen: ":8080",
			CA: config.CAConfig{
				CertFile: "/tmp/aegis-ca.crt",
				KeyFile:  "/tmp/aegis-ca.key",
			},
		},
		Metrics: config.MetricsConfig{Listen: ":9090"},
		Policies: []config.PolicyConfig{{
			Name:     "allow-example",
			Subjects: runtimeTestKubernetesSubjects(),
			Egress: []config.EgressRuleConfig{{
				FQDN:  "example.com",
				Ports: []int{443},
				TLS:   config.TLSRuleConfig{Mode: "passthrough"},
			}},
		}},
		Discovery: runtimeTestKubernetesDiscovery(),
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err == nil {
		t.Fatal("expected buildServers() to fail")
	}
	if got := err.Error(); got != "load mitm engine: bad ca" {
		t.Fatalf("error = %q, want %q", got, "load mitm engine: bad ca")
	}
}

func TestRunBuildsPoliciesFromExplicitSubjectsSchema(t *testing.T) {
	restoreKubernetesProvider := newKubernetesRuntimeProvider
	restoreEC2Provider := newEC2RuntimeProvider
	t.Cleanup(func() {
		newKubernetesRuntimeProvider = restoreKubernetesProvider
		newEC2RuntimeProvider = restoreEC2Provider
	})

	newEC2RuntimeProvider = func(cfg config.EC2DiscoveryConfig, logger *slog.Logger) (identity.RuntimeProvider, error) {
		t.Fatalf("unexpected ec2 provider build for %q", cfg.Name)
		return identity.RuntimeProvider{}, nil
	}
	newKubernetesRuntimeProvider = func(cfg config.KubernetesDiscoveryConfig, logger *slog.Logger) (identity.RuntimeProvider, error) {
		if cfg.Name != "cluster-a" {
			t.Fatalf("provider name = %q, want cluster-a", cfg.Name)
		}
		if cfg.Auth.Provider != "inCluster" {
			t.Fatalf("auth provider = %q, want inCluster", cfg.Auth.Provider)
		}
		return identity.RuntimeProvider{
			Name: "cluster-a",
			Kind: "kubernetes",
			Provider: fakeStartableResolver{
				identity: &identity.Identity{
					Source: "kubernetes",
					Name:   "default/web",
					Labels: map[string]string{
						"kubernetes.io/namespace": "default",
						"app":                     "web",
					},
				},
			},
		}, nil
	}

	configPath := writeRuntimeConfig(t, runtimeConfigYAML("policy-a", ":3128", ":9090", false, ""))
	cfg, err := loadRuntimeConfig(configPath)
	if err != nil {
		t.Fatalf("loadRuntimeConfig() error = %v", err)
	}

	deps, err := buildProxyDependencies(
		context.Background(),
		cfg,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		appmetrics.New(prometheus.NewRegistry()),
		proxy.NewDrainTracker(slog.New(slog.NewTextHandler(io.Discard, nil)), nil),
		proxy.NewConnectionLimiter(slog.New(slog.NewTextHandler(io.Discard, nil)), nil),
		proxy.NewEnforcementOverrideController(slog.New(slog.NewTextHandler(io.Discard, nil))),
	)
	if err != nil {
		t.Fatalf("buildProxyDependencies() error = %v", err)
	}
	if deps.PolicyEngine == nil {
		t.Fatal("PolicyEngine was not built")
	}
	if deps.IdentityResolver == nil {
		t.Fatal("IdentityResolver was not built")
	}

	id, err := deps.IdentityResolver.Resolve(net.ParseIP("10.0.0.10"))
	if err != nil {
		t.Fatalf("IdentityResolver.Resolve() error = %v", err)
	}
	if id == nil {
		t.Fatal("IdentityResolver.Resolve() returned nil identity")
	}

	decision := deps.PolicyEngine.Evaluate(id, netip.MustParseAddr("10.0.0.10"), "example.com", 80, http.MethodGet, "/")
	if decision == nil || !decision.Allowed || decision.Policy != "policy-a" {
		t.Fatalf("decision = %#v, want allowed policy-a decision", decision)
	}
}

func TestRuntimeManagerReloadSwapsHandlerAndCountsSuccess(t *testing.T) {
	stubRuntimeKubernetesProvider(t)
	restoreProxyServer := newProxyServer
	t.Cleanup(func() {
		newProxyServer = restoreProxyServer
	})

	generation := 0
	newProxyServer = func(deps proxy.Dependencies) interface{ Handler() http.Handler } {
		generation++
		body := "generation-1"
		if generation == 2 {
			body = "generation-2"
		}
		return fakeHandlerProvider{handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, body)
		})}
	}

	configPath := writeRuntimeConfig(t, runtimeConfigYAML("policy-a", ":3128", ":9090", false, ""))
	reg := prometheus.NewRegistry()
	m := appmetrics.New(reg)
	handler := &reloadableProxyHandler{}
	manager := newRuntimeManager(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), m, configPath, handler, nil)
	defer manager.Close()

	cfg, err := loadRuntimeConfig(configPath)
	if err != nil {
		t.Fatalf("loadRuntimeConfig() error = %v", err)
	}
	if err := manager.LoadInitial(cfg); err != nil {
		t.Fatalf("LoadInitial() error = %v", err)
	}

	if got := serveReloadableHandler(t, handler); got != "generation-1" {
		t.Fatalf("body = %q, want generation-1", got)
	}

	writeRuntimeConfigAt(t, configPath, runtimeConfigYAML("policy-b", ":3128", ":9090", false, ""))
	if err := manager.ReloadFromFile(); err != nil {
		t.Fatalf("ReloadFromFile() error = %v", err)
	}

	if got := serveReloadableHandler(t, handler); got != "generation-2" {
		t.Fatalf("body = %q, want generation-2", got)
	}
	if got := counterValue(t, reg, "aegis_config_reloads_total", map[string]string{"result": "success"}); got != 1 {
		t.Fatalf("reload success metric = %v, want 1", got)
	}
}

func TestRuntimeManagerReloadFailureKeepsCurrentHandlerAndCountsError(t *testing.T) {
	stubRuntimeKubernetesProvider(t)
	restoreProxyServer := newProxyServer
	t.Cleanup(func() {
		newProxyServer = restoreProxyServer
	})

	newProxyServer = func(deps proxy.Dependencies) interface{ Handler() http.Handler } {
		return fakeHandlerProvider{handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, "stable-generation")
		})}
	}

	configPath := writeRuntimeConfig(t, runtimeConfigYAML("policy-a", ":3128", ":9090", false, ""))
	reg := prometheus.NewRegistry()
	m := appmetrics.New(reg)
	handler := &reloadableProxyHandler{}
	manager := newRuntimeManager(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), m, configPath, handler, nil)
	defer manager.Close()

	cfg, err := loadRuntimeConfig(configPath)
	if err != nil {
		t.Fatalf("loadRuntimeConfig() error = %v", err)
	}
	if err := manager.LoadInitial(cfg); err != nil {
		t.Fatalf("LoadInitial() error = %v", err)
	}

	writeRuntimeConfigAt(t, configPath, runtimeConfigYAML("policy-b", ":4000", ":9090", false, ""))
	if err := manager.ReloadFromFile(); err == nil {
		t.Fatal("expected ReloadFromFile() to fail")
	}

	if got := serveReloadableHandler(t, handler); got != "stable-generation" {
		t.Fatalf("body = %q, want stable-generation", got)
	}
	if got := counterValue(t, reg, "aegis_config_reloads_total", map[string]string{"result": "error"}); got != 1 {
		t.Fatalf("reload error metric = %v, want 1", got)
	}
}

func TestRuntimeManagerAppliesRemotePolicySnapshotUpdate(t *testing.T) {
	restorePolicyDiscoveryRunner := newPolicyDiscoveryRunner
	t.Cleanup(func() {
		newPolicyDiscoveryRunner = restorePolicyDiscoveryRunner
	})

	runner := &fakePolicyDiscoveryRunner{}
	newPolicyDiscoveryRunner = func(ctx context.Context, logger *slog.Logger, sources []config.PolicyDiscoverySourceConfig, apply policyDiscoveryApplyFunc) (policyDiscoveryRunner, error) {
		runner.apply = apply
		runner.sources = append([]config.PolicyDiscoverySourceConfig(nil), sources...)
		return runner, nil
	}

	manager := newRuntimeManager(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), appmetrics.New(prometheus.NewRegistry()), "", &reloadableProxyHandler{}, nil)
	defer manager.Close()

	cfg := testRuntimeConfig()
	cfg.Discovery = config.DiscoveryConfig{
		Policies: []config.PolicyDiscoverySourceConfig{{
			Name:     "remote-a",
			Provider: "aws",
			Bucket:   "policies",
			Prefix:   "env/prod",
		}},
	}
	cfg.Policies = []config.PolicyConfig{
		testRuntimeCIDRPolicy("static-allow", "10.0.0.0/24", "static.example.com"),
	}

	if err := manager.LoadInitial(cfg); err != nil {
		t.Fatalf("LoadInitial() error = %v", err)
	}
	if runner.apply == nil {
		t.Fatal("expected policy discovery apply callback")
	}

	before, err := manager.Simulate(appmetrics.SimulationRequest{
		Protocol: "connect",
		SourceIP: "10.1.0.10",
		FQDN:     "remote.example.com",
		Port:     443,
	})
	if err != nil {
		t.Fatalf("Simulate() before update error = %v", err)
	}
	if before.Decision == nil || before.Decision.Policy != "" || before.Decision.Allowed {
		t.Fatalf("Simulate() decision before update = %#v, want empty deny result", before.Decision)
	}

	err = runner.apply("remote-a", policydiscovery.Snapshot{
		Source: config.PolicyDiscoverySourceConfig{Name: "remote-a"},
		Policies: []policydiscovery.DiscoveredPolicy{{
			SourceName: "remote-a",
			Object: policydiscovery.ObjectRef{
				Key:      "env/prod/remote.yaml",
				URI:      "s3://policies/env/prod/remote.yaml",
				Revision: "\"etag-1\"",
			},
			Policy: testRuntimeCIDRPolicy("remote-allow", "10.1.0.0/24", "remote.example.com"),
		}},
	})
	if err != nil {
		t.Fatalf("apply remote snapshot error = %v", err)
	}

	after, err := manager.Simulate(appmetrics.SimulationRequest{
		Protocol: "connect",
		SourceIP: "10.1.0.10",
		FQDN:     "remote.example.com",
		Port:     443,
	})
	if err != nil {
		t.Fatalf("Simulate() after update error = %v", err)
	}
	if after.Decision == nil || after.Decision.Policy != "remote-allow" || !after.Decision.Allowed {
		t.Fatalf("Simulate() decision after update = %#v, want allowed remote-allow", after.Decision)
	}
	if len(manager.current.remoteSnapshots) != 1 {
		t.Fatalf("remoteSnapshots len = %d, want 1", len(manager.current.remoteSnapshots))
	}
	if got := policyNames(manager.current.mergedPolicies); !slices.Equal(got, []string{"static-allow", "remote-allow"}) {
		t.Fatalf("merged policy names = %#v, want %#v", got, []string{"static-allow", "remote-allow"})
	}
}

func TestRuntimeManagerKeepsLastGoodRemotePolicySnapshotOnFailure(t *testing.T) {
	restorePolicyDiscoveryRunner := newPolicyDiscoveryRunner
	t.Cleanup(func() {
		newPolicyDiscoveryRunner = restorePolicyDiscoveryRunner
	})

	runner := &fakePolicyDiscoveryRunner{}
	newPolicyDiscoveryRunner = func(ctx context.Context, logger *slog.Logger, sources []config.PolicyDiscoverySourceConfig, apply policyDiscoveryApplyFunc) (policyDiscoveryRunner, error) {
		runner.apply = apply
		runner.sources = append([]config.PolicyDiscoverySourceConfig(nil), sources...)
		return runner, nil
	}

	manager := newRuntimeManager(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), appmetrics.New(prometheus.NewRegistry()), "", &reloadableProxyHandler{}, nil)
	defer manager.Close()

	cfg := testRuntimeConfig()
	cfg.Discovery = config.DiscoveryConfig{
		Policies: []config.PolicyDiscoverySourceConfig{{
			Name:     "remote-a",
			Provider: "aws",
			Bucket:   "policies",
		}},
	}
	cfg.Policies = []config.PolicyConfig{
		testRuntimeCIDRPolicy("static-allow", "10.0.0.0/24", "static.example.com"),
	}

	if err := manager.LoadInitial(cfg); err != nil {
		t.Fatalf("LoadInitial() error = %v", err)
	}

	goodSnapshot := policydiscovery.Snapshot{
		Source: config.PolicyDiscoverySourceConfig{Name: "remote-a"},
		Policies: []policydiscovery.DiscoveredPolicy{{
			SourceName: "remote-a",
			Object: policydiscovery.ObjectRef{
				Key: "env/prod/good.yaml",
				URI: "s3://policies/env/prod/good.yaml",
			},
			Policy: testRuntimeCIDRPolicy("remote-allow", "10.1.0.0/24", "remote.example.com"),
		}},
	}
	if err := runner.apply("remote-a", goodSnapshot); err != nil {
		t.Fatalf("apply good snapshot error = %v", err)
	}

	badSnapshot := policydiscovery.Snapshot{
		Source: config.PolicyDiscoverySourceConfig{Name: "remote-a"},
		Policies: []policydiscovery.DiscoveredPolicy{{
			SourceName: "remote-a",
			Object: policydiscovery.ObjectRef{
				Key: "env/prod/bad.yaml",
				URI: "s3://policies/env/prod/bad.yaml",
			},
			Policy: testRuntimeCIDRPolicy("static-allow", "10.2.0.0/24", "duplicate.example.com"),
		}},
	}
	err := runner.apply("remote-a", badSnapshot)
	if err == nil {
		t.Fatal("expected duplicate remote snapshot update to fail")
	}

	after, err := manager.Simulate(appmetrics.SimulationRequest{
		Protocol: "connect",
		SourceIP: "10.1.0.10",
		FQDN:     "remote.example.com",
		Port:     443,
	})
	if err != nil {
		t.Fatalf("Simulate() after failed update error = %v", err)
	}
	if after.Decision == nil || after.Decision.Policy != "remote-allow" || !after.Decision.Allowed {
		t.Fatalf("Simulate() decision after failed update = %#v, want retained remote-allow", after.Decision)
	}
	if got := policyNames(manager.current.mergedPolicies); !slices.Equal(got, []string{"static-allow", "remote-allow"}) {
		t.Fatalf("merged policy names = %#v, want %#v", got, []string{"static-allow", "remote-allow"})
	}
	if got := manager.current.remoteSnapshots["remote-a"].Policies[0].Policy.Name; got != "remote-allow" {
		t.Fatalf("retained remote policy = %q, want remote-allow", got)
	}
}

func TestRuntimeManagerReloadReplacesPolicyDiscoveryRunnerLifecycle(t *testing.T) {
	restorePolicyDiscoveryRunner := newPolicyDiscoveryRunner
	t.Cleanup(func() {
		newPolicyDiscoveryRunner = restorePolicyDiscoveryRunner
	})

	var runners []*fakePolicyDiscoveryRunner
	newPolicyDiscoveryRunner = func(ctx context.Context, logger *slog.Logger, sources []config.PolicyDiscoverySourceConfig, apply policyDiscoveryApplyFunc) (policyDiscoveryRunner, error) {
		runner := &fakePolicyDiscoveryRunner{
			apply:   apply,
			sources: append([]config.PolicyDiscoverySourceConfig(nil), sources...),
		}
		runners = append(runners, runner)
		return runner, nil
	}

	manager := newRuntimeManager(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), appmetrics.New(prometheus.NewRegistry()), "", &reloadableProxyHandler{}, nil)

	cfg := testRuntimeConfig()
	cfg.Discovery = config.DiscoveryConfig{
		Policies: []config.PolicyDiscoverySourceConfig{{
			Name:     "remote-a",
			Provider: "aws",
			Bucket:   "policies",
		}},
	}
	cfg.Policies = []config.PolicyConfig{
		testRuntimeCIDRPolicy("static-allow", "10.0.0.0/24", "static.example.com"),
	}

	if err := manager.LoadInitial(cfg); err != nil {
		t.Fatalf("LoadInitial() error = %v", err)
	}

	nextCfg := cfg
	nextCfg.Policies = []config.PolicyConfig{
		testRuntimeCIDRPolicy("static-next", "10.2.0.0/24", "next.example.com"),
	}
	if err := manager.applyConfig(nextCfg, true); err != nil {
		t.Fatalf("applyConfig() error = %v", err)
	}

	if len(runners) != 2 {
		t.Fatalf("runner creations = %d, want 2", len(runners))
	}
	if runners[0].startCalls != 1 {
		t.Fatalf("first runner start calls = %d, want 1", runners[0].startCalls)
	}
	if runners[1].startCalls != 1 {
		t.Fatalf("second runner start calls = %d, want 1", runners[1].startCalls)
	}
	if runners[0].closeCalls != 1 {
		t.Fatalf("first runner close calls = %d, want 1", runners[0].closeCalls)
	}
	if runners[1].closeCalls != 0 {
		t.Fatalf("second runner close calls before manager close = %d, want 0", runners[1].closeCalls)
	}

	manager.Close()

	if runners[1].closeCalls != 1 {
		t.Fatalf("second runner close calls after manager close = %d, want 1", runners[1].closeCalls)
	}
}

func TestRuntimeManagerRejectsStaleDiscoveryCallbackAfterReloadAndClose(t *testing.T) {
	restorePolicyDiscoveryRunner := newPolicyDiscoveryRunner
	t.Cleanup(func() {
		newPolicyDiscoveryRunner = restorePolicyDiscoveryRunner
	})

	var runners []*fakePolicyDiscoveryRunner
	newPolicyDiscoveryRunner = func(ctx context.Context, logger *slog.Logger, sources []config.PolicyDiscoverySourceConfig, apply policyDiscoveryApplyFunc) (policyDiscoveryRunner, error) {
		runner := &fakePolicyDiscoveryRunner{
			apply:   apply,
			sources: append([]config.PolicyDiscoverySourceConfig(nil), sources...),
		}
		runners = append(runners, runner)
		return runner, nil
	}

	manager := newRuntimeManager(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), appmetrics.New(prometheus.NewRegistry()), "", &reloadableProxyHandler{}, nil)

	cfg := testRuntimeConfig()
	cfg.Discovery = config.DiscoveryConfig{
		Policies: []config.PolicyDiscoverySourceConfig{{
			Name:     "remote-a",
			Provider: "aws",
			Bucket:   "policies",
		}},
	}
	cfg.Policies = []config.PolicyConfig{
		testRuntimeCIDRPolicy("static-allow", "10.0.0.0/24", "static.example.com"),
	}

	if err := manager.LoadInitial(cfg); err != nil {
		t.Fatalf("LoadInitial() error = %v", err)
	}

	nextCfg := cfg
	nextCfg.Policies = []config.PolicyConfig{
		testRuntimeCIDRPolicy("static-next", "10.2.0.0/24", "next.example.com"),
	}
	if err := manager.applyConfig(nextCfg, true); err != nil {
		t.Fatalf("applyConfig() error = %v", err)
	}

	staleSnapshot := policydiscovery.Snapshot{
		Source: config.PolicyDiscoverySourceConfig{Name: "remote-a"},
		Policies: []policydiscovery.DiscoveredPolicy{{
			SourceName: "remote-a",
			Object: policydiscovery.ObjectRef{
				Key: "env/prod/stale.yaml",
				URI: "s3://policies/env/prod/stale.yaml",
			},
			Policy: testRuntimeCIDRPolicy("stale-allow", "10.3.0.0/24", "stale.example.com"),
		}},
	}
	if err := runners[0].apply("remote-a", staleSnapshot); !errors.Is(err, context.Canceled) {
		t.Fatalf("stale callback after reload error = %v, want context.Canceled", err)
	}
	if got := policyNames(manager.current.mergedPolicies); !slices.Equal(got, []string{"static-next"}) {
		t.Fatalf("merged policy names after stale reload callback = %#v, want %#v", got, []string{"static-next"})
	}

	manager.Close()

	if err := runners[1].apply("remote-a", staleSnapshot); !errors.Is(err, context.Canceled) {
		t.Fatalf("stale callback after close error = %v, want context.Canceled", err)
	}
	if len(manager.current.mergedPolicies) != 0 {
		t.Fatalf("merged policies after close = %#v, want empty", manager.current.mergedPolicies)
	}
}

func TestRuntimeManagerAppliesInitialSnapshotDeliveredDuringRunnerStart(t *testing.T) {
	restorePolicyDiscoveryRunner := newPolicyDiscoveryRunner
	t.Cleanup(func() {
		newPolicyDiscoveryRunner = restorePolicyDiscoveryRunner
	})

	newPolicyDiscoveryRunner = func(ctx context.Context, logger *slog.Logger, sources []config.PolicyDiscoverySourceConfig, apply policyDiscoveryApplyFunc) (policyDiscoveryRunner, error) {
		return &fakePolicyDiscoveryRunner{
			apply:   apply,
			sources: append([]config.PolicyDiscoverySourceConfig(nil), sources...),
			startFn: func(r *fakePolicyDiscoveryRunner) error {
				return r.apply("remote-a", policydiscovery.Snapshot{
					Source: config.PolicyDiscoverySourceConfig{Name: "remote-a"},
					Policies: []policydiscovery.DiscoveredPolicy{{
						SourceName: "remote-a",
						Object: policydiscovery.ObjectRef{
							Key: "env/prod/initial.yaml",
							URI: "s3://policies/env/prod/initial.yaml",
						},
						Policy: testRuntimeCIDRPolicy("remote-allow", "10.1.0.0/24", "remote.example.com"),
					}},
				})
			},
		}, nil
	}

	manager := newRuntimeManager(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), appmetrics.New(prometheus.NewRegistry()), "", &reloadableProxyHandler{}, nil)
	defer manager.Close()

	cfg := testRuntimeConfig()
	cfg.Discovery = config.DiscoveryConfig{
		Policies: []config.PolicyDiscoverySourceConfig{{
			Name:     "remote-a",
			Provider: "aws",
			Bucket:   "policies",
		}},
	}
	cfg.Policies = []config.PolicyConfig{
		testRuntimeCIDRPolicy("static-allow", "10.0.0.0/24", "static.example.com"),
	}

	if err := manager.LoadInitial(cfg); err != nil {
		t.Fatalf("LoadInitial() error = %v", err)
	}

	if got := policyNames(manager.current.mergedPolicies); !slices.Equal(got, []string{"static-allow", "remote-allow"}) {
		t.Fatalf("merged policy names = %#v, want %#v", got, []string{"static-allow", "remote-allow"})
	}

	resp, err := manager.Simulate(appmetrics.SimulationRequest{
		Protocol: "connect",
		SourceIP: "10.1.0.10",
		FQDN:     "remote.example.com",
		Port:     443,
	})
	if err != nil {
		t.Fatalf("Simulate() error = %v", err)
	}
	if resp.Decision == nil || resp.Decision.Policy != "remote-allow" || !resp.Decision.Allowed {
		t.Fatalf("Simulate() decision = %#v, want allowed remote-allow", resp.Decision)
	}
}

func TestRuntimeManagerClosePreventsPendingGenerationActivation(t *testing.T) {
	restorePolicyDiscoveryRunner := newPolicyDiscoveryRunner
	t.Cleanup(func() {
		newPolicyDiscoveryRunner = restorePolicyDiscoveryRunner
	})

	constructorEntered := make(chan struct{})
	releaseConstructor := make(chan struct{})
	newPolicyDiscoveryRunner = func(ctx context.Context, logger *slog.Logger, sources []config.PolicyDiscoverySourceConfig, apply policyDiscoveryApplyFunc) (policyDiscoveryRunner, error) {
		close(constructorEntered)
		<-releaseConstructor
		return &fakePolicyDiscoveryRunner{
			apply:   apply,
			sources: append([]config.PolicyDiscoverySourceConfig(nil), sources...),
		}, nil
	}

	manager := newRuntimeManager(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), appmetrics.New(prometheus.NewRegistry()), "", &reloadableProxyHandler{}, nil)

	cfg := testRuntimeConfig()
	cfg.Discovery = config.DiscoveryConfig{
		Policies: []config.PolicyDiscoverySourceConfig{{
			Name:     "remote-a",
			Provider: "aws",
			Bucket:   "policies",
		}},
	}
	cfg.Policies = []config.PolicyConfig{
		testRuntimeCIDRPolicy("static-allow", "10.0.0.0/24", "static.example.com"),
	}

	loadErrCh := make(chan error, 1)
	go func() {
		loadErrCh <- manager.LoadInitial(cfg)
	}()

	<-constructorEntered
	manager.Close()
	close(releaseConstructor)

	if err := <-loadErrCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("LoadInitial() error = %v, want context.Canceled", err)
	}
	if manager.current.id != 0 {
		t.Fatalf("current generation id = %d, want 0", manager.current.id)
	}
	if len(manager.current.mergedPolicies) != 0 {
		t.Fatalf("merged policies = %#v, want empty", manager.current.mergedPolicies)
	}
}

func TestValidateReloadableConfigRejectsProxyProtocolChange(t *testing.T) {
	current := testRuntimeConfig()
	next := testRuntimeConfig()
	next.Proxy.ProxyProtocol.Enabled = true

	err := validateReloadableConfig(current, next)
	if err == nil {
		t.Fatal("expected validateReloadableConfig() to fail")
	}
	if got := err.Error(); got != "proxy.proxyProtocol.enabled cannot change during reload" {
		t.Fatalf("error = %q, want %q", got, "proxy.proxyProtocol.enabled cannot change during reload")
	}
}

func TestValidateReloadableConfigRejectsAdminListenerChange(t *testing.T) {
	current := testRuntimeConfig()
	current.Admin = config.AdminConfig{Enabled: true, Listen: "127.0.0.1:9091", Token: "secret"}
	next := current
	next.Admin.Listen = "127.0.0.1:9092"

	err := validateReloadableConfig(current, next)
	if err == nil {
		t.Fatal("expected validateReloadableConfig() to fail")
	}
	if got := err.Error(); got != "admin.listen cannot change during reload" {
		t.Fatalf("error = %q, want %q", got, "admin.listen cannot change during reload")
	}
}

func TestValidateReloadableConfigRejectsPprofEnablementChange(t *testing.T) {
	current := testRuntimeConfig()
	next := current
	next.Pprof.Enabled = true
	next.Pprof.Listen = "127.0.0.1:6060"

	err := validateReloadableConfig(current, next)
	if err == nil {
		t.Fatal("expected validateReloadableConfig() to fail")
	}
	if got := err.Error(); got != "pprof.enabled cannot change during reload" {
		t.Fatalf("error = %q, want %q", got, "pprof.enabled cannot change during reload")
	}
}

func TestValidateReloadableConfigRejectsPprofListenerChange(t *testing.T) {
	current := testRuntimeConfig()
	current.Pprof = config.PprofConfig{Enabled: true, Listen: "127.0.0.1:6060"}
	next := current
	next.Pprof.Listen = "127.0.0.1:6061"

	err := validateReloadableConfig(current, next)
	if err == nil {
		t.Fatal("expected validateReloadableConfig() to fail")
	}
	if got := err.Error(); got != "pprof.listen cannot change during reload" {
		t.Fatalf("error = %q, want %q", got, "pprof.listen cannot change during reload")
	}
}

func TestRuntimeManagerShutdownGracePeriodUsesConfigValue(t *testing.T) {
	manager := &runtimeManager{}
	manager.current.cfg.Shutdown.GracePeriod = 17 * time.Second

	if got := manager.ShutdownGracePeriod(); got != 17*time.Second {
		t.Fatalf("ShutdownGracePeriod() = %v, want %v", got, 17*time.Second)
	}
}

func TestRuntimeManagerShutdownGracePeriodFallsBackToDefault(t *testing.T) {
	manager := &runtimeManager{}

	if got := manager.ShutdownGracePeriod(); got != 10*time.Second {
		t.Fatalf("ShutdownGracePeriod() = %v, want %v", got, 10*time.Second)
	}
}

func TestRuntimeManagerReloadTracksMITMCARotationAndCacheReset(t *testing.T) {
	stubRuntimeKubernetesProvider(t)
	certA, keyA := writeTestCAFiles(t, "Aegis Test CA A")
	certB, keyB := writeTestCAFiles(t, "Aegis Test CA B")

	configPath := writeRuntimeConfig(t, runtimeConfigYAMLWithCA("policy-a", ":3128", ":9090", certA, keyA))
	reg := prometheus.NewRegistry()
	m := appmetrics.New(reg)
	handler := &reloadableProxyHandler{}
	manager := newRuntimeManager(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), m, configPath, handler, nil)
	defer manager.Close()

	cfg, err := loadRuntimeConfig(configPath)
	if err != nil {
		t.Fatalf("loadRuntimeConfig() error = %v", err)
	}
	if err := manager.LoadInitial(cfg); err != nil {
		t.Fatalf("LoadInitial() error = %v", err)
	}
	if manager.current.mitm == nil {
		t.Fatal("expected initial MITM engine")
	}

	if _, _, err := manager.current.mitm.CertificateForSNI("example.com"); err != nil {
		t.Fatalf("CertificateForSNI() error = %v", err)
	}
	if got := gaugeValue(t, reg, "aegis_mitm_certificate_cache_entries"); got != 1 {
		t.Fatalf("cache entries gauge = %v, want 1", got)
	}

	writeRuntimeConfigAt(t, configPath, runtimeConfigYAMLWithCA("policy-b", ":3128", ":9090", certB, keyB))
	if err := manager.ReloadFromFile(); err != nil {
		t.Fatalf("ReloadFromFile() error = %v", err)
	}

	if got := counterValue(t, reg, "aegis_mitm_ca_cycles_total", map[string]string{"result": "initial"}); got != 1 {
		t.Fatalf("initial mitm ca metric = %v, want 1", got)
	}
	if got := counterValue(t, reg, "aegis_mitm_ca_cycles_total", map[string]string{"result": "rotated"}); got != 1 {
		t.Fatalf("rotated mitm ca metric = %v, want 1", got)
	}
	if got := counterValue(t, reg, "aegis_mitm_certificate_cache_evictions_total", map[string]string{"reason": "rotation"}); got != 1 {
		t.Fatalf("cache eviction metric = %v, want 1", got)
	}
	if got := gaugeValue(t, reg, "aegis_mitm_certificate_cache_entries"); got != 0 {
		t.Fatalf("cache entries gauge = %v, want 0", got)
	}
}

func TestRuntimeManagerReloadTracksUnchangedMITMCAAndCacheReset(t *testing.T) {
	stubRuntimeKubernetesProvider(t)
	certFile, keyFile := writeTestCAFiles(t, "Aegis Test CA")

	configPath := writeRuntimeConfig(t, runtimeConfigYAMLWithCA("policy-a", ":3128", ":9090", certFile, keyFile))
	reg := prometheus.NewRegistry()
	m := appmetrics.New(reg)
	handler := &reloadableProxyHandler{}
	manager := newRuntimeManager(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), m, configPath, handler, nil)
	defer manager.Close()

	cfg, err := loadRuntimeConfig(configPath)
	if err != nil {
		t.Fatalf("loadRuntimeConfig() error = %v", err)
	}
	if err := manager.LoadInitial(cfg); err != nil {
		t.Fatalf("LoadInitial() error = %v", err)
	}
	if _, _, err := manager.current.mitm.CertificateForSNI("example.com"); err != nil {
		t.Fatalf("CertificateForSNI() error = %v", err)
	}

	writeRuntimeConfigAt(t, configPath, runtimeConfigYAMLWithCA("policy-b", ":3128", ":9090", certFile, keyFile))
	if err := manager.ReloadFromFile(); err != nil {
		t.Fatalf("ReloadFromFile() error = %v", err)
	}

	if got := counterValue(t, reg, "aegis_mitm_ca_cycles_total", map[string]string{"result": "unchanged"}); got != 1 {
		t.Fatalf("unchanged mitm ca metric = %v, want 1", got)
	}
	if got := counterValue(t, reg, "aegis_mitm_certificate_cache_evictions_total", map[string]string{"reason": "reload"}); got != 1 {
		t.Fatalf("cache eviction metric = %v, want 1", got)
	}
	if got := gaugeValue(t, reg, "aegis_mitm_certificate_cache_entries"); got != 0 {
		t.Fatalf("cache entries gauge = %v, want 0", got)
	}
}

func TestRuntimeManagerReloadTracksCompanionOnlyMITMCAChanges(t *testing.T) {
	stubRuntimeKubernetesProvider(t)
	issuerCert, issuerKey := writeTestCAFiles(t, "Issuer CA")
	companionACert, companionAKey := writeTestCAFiles(t, "Companion A")
	companionBCert, companionBKey := writeTestCAFiles(t, "Companion B")

	configPath := writeRuntimeConfig(t, runtimeConfigYAMLWithAdditionalCAs(
		"policy-a",
		":3128",
		":9090",
		issuerCert,
		issuerKey,
		[][2]string{
			{companionACert, companionAKey},
			{companionBCert, companionBKey},
		},
	))

	reg := prometheus.NewRegistry()
	manager := newRuntimeManager(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), appmetrics.New(reg), configPath, &reloadableProxyHandler{}, nil)
	defer manager.Close()

	cfg, err := loadRuntimeConfig(configPath)
	if err != nil {
		t.Fatalf("loadRuntimeConfig() error = %v", err)
	}
	if err := manager.LoadInitial(cfg); err != nil {
		t.Fatalf("LoadInitial() error = %v", err)
	}
	if _, _, err := manager.current.mitm.CertificateForSNI("example.com"); err != nil {
		t.Fatalf("CertificateForSNI() error = %v", err)
	}
	if got := gaugeValue(t, reg, "aegis_mitm_certificate_cache_entries"); got != 1 {
		t.Fatalf("cache entries gauge = %v, want 1", got)
	}

	writeRuntimeConfigAt(t, configPath, runtimeConfigYAMLWithAdditionalCAs(
		"policy-b",
		":3128",
		":9090",
		issuerCert,
		issuerKey,
		[][2]string{
			{companionBCert, companionBKey},
			{companionACert, companionAKey},
		},
	))
	if err := manager.ReloadFromFile(); err != nil {
		t.Fatalf("ReloadFromFile() error = %v", err)
	}

	if got := counterValue(t, reg, "aegis_mitm_ca_cycles_total", map[string]string{"result": "companions_changed"}); got != 1 {
		t.Fatalf("companions_changed metric = %v, want 1", got)
	}
	if got := counterValue(t, reg, "aegis_mitm_ca_cycles_total", map[string]string{"result": "unchanged"}); got != 0 {
		t.Fatalf("unchanged metric = %v, want 0", got)
	}
	if got := counterValue(t, reg, "aegis_mitm_ca_cycles_total", map[string]string{"result": "rotated"}); got != 0 {
		t.Fatalf("rotated metric = %v, want 0", got)
	}
	if got := counterValue(t, reg, "aegis_mitm_certificate_cache_evictions_total", map[string]string{"reason": "reload"}); got != 1 {
		t.Fatalf("reload eviction metric = %v, want 1", got)
	}
	if got := counterValue(t, reg, "aegis_mitm_certificate_cache_evictions_total", map[string]string{"reason": "rotation"}); got != 0 {
		t.Fatalf("rotation eviction metric = %v, want 0", got)
	}
	if got := gaugeValue(t, reg, "aegis_mitm_certificate_cache_entries"); got != 0 {
		t.Fatalf("cache entries gauge = %v, want 0", got)
	}
}

func TestRuntimeManagerReloadRejectsInvalidCompanionCA(t *testing.T) {
	stubRuntimeKubernetesProvider(t)
	issuerCert, issuerKey := writeTestCAFiles(t, "Issuer CA")
	configPath := writeRuntimeConfig(t, runtimeConfigYAMLWithCA("policy-a", ":3128", ":9090", issuerCert, issuerKey))

	manager := newRuntimeManager(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), appmetrics.New(prometheus.NewRegistry()), configPath, &reloadableProxyHandler{}, nil)
	defer manager.Close()

	cfg, err := loadRuntimeConfig(configPath)
	if err != nil {
		t.Fatalf("loadRuntimeConfig() error = %v", err)
	}
	if err := manager.LoadInitial(cfg); err != nil {
		t.Fatalf("LoadInitial() error = %v", err)
	}

	badKeyPath := filepath.Join(t.TempDir(), "broken-companion.key")
	if err := os.WriteFile(badKeyPath, []byte("broken-key"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	writeRuntimeConfigAt(t, configPath, runtimeConfigYAMLWithAdditionalCAs(
		"policy-b",
		":3128",
		":9090",
		issuerCert,
		issuerKey,
		[][2]string{{issuerCert, badKeyPath}},
	))

	if err := manager.ReloadFromFile(); err == nil {
		t.Fatal("expected ReloadFromFile() to fail for invalid companion CA material")
	}
	if status := manager.RuntimeStatus(); status.MITM == nil || len(status.MITM.CompanionFingerprints) != 0 {
		t.Fatalf("RuntimeStatus().MITM = %#v, want unchanged previous generation", status.MITM)
	}
}

func TestRuntimeManagerRuntimeStatusIncludesMITMCASet(t *testing.T) {
	stubRuntimeKubernetesProvider(t)
	certA, keyA := writeTestCAFiles(t, "Primary CA")
	certB, keyB := writeTestCAFiles(t, "Companion CA")

	configPath := writeRuntimeConfig(t, runtimeConfigYAMLWithAdditionalCAs(
		"policy-a",
		":3128",
		":9090",
		certA,
		keyA,
		[][2]string{{certB, keyB}},
	))

	manager := newRuntimeManager(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), appmetrics.New(prometheus.NewRegistry()), configPath, &reloadableProxyHandler{}, nil)
	defer manager.Close()

	cfg, err := loadRuntimeConfig(configPath)
	if err != nil {
		t.Fatalf("loadRuntimeConfig() error = %v", err)
	}
	if err := manager.LoadInitial(cfg); err != nil {
		t.Fatalf("LoadInitial() error = %v", err)
	}

	status := manager.RuntimeStatus()
	if status.MITM == nil || !status.MITM.Enabled {
		t.Fatalf("RuntimeStatus().MITM = %#v, want enabled MITM status", status.MITM)
	}
	if len(status.MITM.CompanionFingerprints) != 1 {
		t.Fatalf("CompanionFingerprints = %#v, want one companion", status.MITM.CompanionFingerprints)
	}
}

func TestRuntimeManagerEnforcementOverridePersistsAcrossReload(t *testing.T) {
	stubRuntimeKubernetesProvider(t)
	configPath := writeRuntimeConfig(t, runtimeConfigYAML("policy-a", ":3128", ":9090", false, ""))
	reg := prometheus.NewRegistry()
	m := appmetrics.New(reg)
	handler := &reloadableProxyHandler{}
	manager := newRuntimeManager(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), m, configPath, handler, nil)
	defer manager.Close()

	cfg, err := loadRuntimeConfig(configPath)
	if err != nil {
		t.Fatalf("loadRuntimeConfig() error = %v", err)
	}
	if err := manager.LoadInitial(cfg); err != nil {
		t.Fatalf("LoadInitial() error = %v", err)
	}

	status, err := manager.SetEnforcementMode("audit")
	if err != nil {
		t.Fatalf("SetEnforcementMode() error = %v", err)
	}
	if status.Override != "audit" || status.Effective != "audit" {
		t.Fatalf("status = %#v, want override and effective audit", status)
	}

	writeRuntimeConfigAt(t, configPath, runtimeConfigYAML("policy-b", ":3128", ":9090", false, ""))
	if err := manager.ReloadFromFile(); err != nil {
		t.Fatalf("ReloadFromFile() error = %v", err)
	}

	status = manager.EnforcementStatus()
	if status.Configured != config.EnforcementEnforce || status.Override != "audit" || status.Effective != "audit" {
		t.Fatalf("status after reload = %#v, want configured enforce and override/effective audit", status)
	}
	if got := mustFindMetric(t, reg, "aegis_enforcement_mode", map[string]string{"scope": "override", "mode": "audit"}).GetGauge().GetValue(); got != 1 {
		t.Fatalf("override mode gauge = %v, want 1", got)
	}

	status, err = manager.SetEnforcementMode("config")
	if err != nil {
		t.Fatalf("SetEnforcementMode(config) error = %v", err)
	}
	if status.Override != "" || status.Effective != config.EnforcementEnforce {
		t.Fatalf("status after clear = %#v, want configured-only enforce", status)
	}
}

func TestRuntimeManagerDumpIdentitiesReturnsCompositeRecords(t *testing.T) {
	manager := &runtimeManager{
		enforcement: proxy.NewEnforcementOverrideController(slog.New(slog.NewTextHandler(io.Discard, nil))),
	}
	manager.current.identityResolver = fakeDumpResolver{
		entries: []identity.DumpEntry{{
			IP: "10.0.0.10",
			Effective: &identity.Mapping{
				IP:       "10.0.0.10",
				Provider: "cluster-a",
				Kind:     "kubernetes",
				Identity: &identity.Identity{
					Name:     "default/api",
					Source:   "ec2",
					Provider: "stale-provider",
				},
			},
			Shadows: []identity.Mapping{{
				IP:       "10.0.0.10",
				Provider: "production-ec2",
				Kind:     "ec2",
				Identity: &identity.Identity{
					Name:     "i-shadow",
					Source:   "kubernetes",
					Provider: "other-stale-provider",
				},
			}},
		}},
	}

	records := manager.DumpIdentities()
	if len(records) != 1 || records[0].IP != "10.0.0.10" {
		t.Fatalf("records = %#v, want one dump record", records)
	}
	if records[0].Effective == nil || records[0].Effective.Name != "default/api" {
		t.Fatalf("effective identity = %#v, want default/api", records[0].Effective)
	}
	if records[0].Effective.Provider != "cluster-a" || records[0].Effective.Source != "kubernetes" || records[0].Effective.Kind != "kubernetes" {
		t.Fatalf("effective record = %#v, want authoritative provider/source/kind", records[0].Effective)
	}
	if len(records[0].Shadows) != 1 {
		t.Fatalf("shadows = %#v, want one shadow", records[0].Shadows)
	}
	if records[0].Shadows[0].Provider != "production-ec2" || records[0].Shadows[0].Source != "ec2" || records[0].Shadows[0].Kind != "ec2" {
		t.Fatalf("shadow record = %#v, want authoritative provider/source/kind", records[0].Shadows[0])
	}
}

func TestRuntimeManagerSimulateDeniesUnknownIdentityWhenConfigured(t *testing.T) {
	manager := &runtimeManager{
		enforcement: proxy.NewEnforcementOverrideController(slog.New(slog.NewTextHandler(io.Discard, nil))),
	}
	manager.current.cfg = testRuntimeConfig()
	manager.current.cfg.Proxy.UnknownIdentityPolicy = config.UnknownIdentityDeny

	resp, err := manager.Simulate(appmetrics.SimulationRequest{
		SourceIP: "10.0.0.10",
		FQDN:     "example.com",
		Port:     443,
		Protocol: "connect",
	})
	if err != nil {
		t.Fatalf("Simulate() error = %v", err)
	}
	if resp.Action != "deny" || resp.Reason != "unknown_identity" {
		t.Fatalf("response = %#v, want deny unknown_identity", resp)
	}
}

func TestRuntimeManagerSimulateAllowsCIDRSubjectWithoutIdentity(t *testing.T) {
	manager := &runtimeManager{
		enforcement: proxy.NewEnforcementOverrideController(slog.New(slog.NewTextHandler(io.Discard, nil))),
	}
	manager.current.cfg = testRuntimeConfig()
	manager.current.cfg.Proxy.UnknownIdentityPolicy = config.UnknownIdentityDeny
	manager.current.identityResolver = fakeIdentityResolver{}

	engine, err := policy.NewEngine([]config.PolicyConfig{{
		Name: "allow-source-cidr",
		Subjects: config.PolicySubjectsConfig{
			CIDRs: []string{"10.0.0.0/24"},
		},
		Egress: []config.EgressRuleConfig{{
			FQDN:  "example.com",
			Ports: []int{80},
			TLS:   config.TLSRuleConfig{Mode: "mitm"},
			HTTP: &config.HTTPRuleConfig{
				AllowedMethods: []string{"GET"},
				AllowedPaths:   []string{"/allowed"},
			},
		}},
	}})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	manager.current.policyEngine = engine

	resp, err := manager.Simulate(appmetrics.SimulationRequest{
		SourceIP: "10.0.0.10",
		FQDN:     "example.com",
		Port:     80,
		Protocol: "http",
		Method:   http.MethodGet,
		Path:     "/allowed",
	})
	if err != nil {
		t.Fatalf("Simulate() error = %v", err)
	}
	if resp.Identity == nil || !resp.UnknownIdentity {
		t.Fatalf("identity = %#v, unknownIdentity = %v, want unknown identity record", resp.Identity, resp.UnknownIdentity)
	}
	if resp.Action != "allow" || resp.Reason != "policy_allowed" {
		t.Fatalf("response = %#v, want allow policy_allowed", resp)
	}
	if resp.Decision == nil || resp.Decision.Policy != "allow-source-cidr" {
		t.Fatalf("decision = %#v, want allow-source-cidr", resp.Decision)
	}
}

func TestRuntimeManagerSimulateAllowsCIDRSubjectWhenIdentityResolverErrors(t *testing.T) {
	manager := &runtimeManager{
		logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		enforcement: proxy.NewEnforcementOverrideController(slog.New(slog.NewTextHandler(io.Discard, nil))),
	}
	manager.current.cfg = testRuntimeConfig()
	manager.current.cfg.Proxy.UnknownIdentityPolicy = config.UnknownIdentityDeny
	manager.current.identityResolver = fakeIdentityResolver{err: errors.New("boom")}

	engine, err := policy.NewEngine([]config.PolicyConfig{{
		Name: "allow-source-cidr",
		Subjects: config.PolicySubjectsConfig{
			CIDRs: []string{"10.0.0.0/24"},
		},
		Egress: []config.EgressRuleConfig{{
			FQDN:  "example.com",
			Ports: []int{80},
			TLS:   config.TLSRuleConfig{Mode: "mitm"},
			HTTP: &config.HTTPRuleConfig{
				AllowedMethods: []string{"GET"},
				AllowedPaths:   []string{"/allowed"},
			},
		}},
	}})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	manager.current.policyEngine = engine

	resp, err := manager.Simulate(appmetrics.SimulationRequest{
		SourceIP: "10.0.0.10",
		FQDN:     "example.com",
		Port:     80,
		Protocol: "http",
		Method:   http.MethodGet,
		Path:     "/allowed",
	})
	if err != nil {
		t.Fatalf("Simulate() error = %v", err)
	}
	if resp.Identity == nil || !resp.UnknownIdentity {
		t.Fatalf("identity = %#v, unknownIdentity = %v, want unknown identity record", resp.Identity, resp.UnknownIdentity)
	}
	if resp.Action != "allow" || resp.Reason != "policy_allowed" {
		t.Fatalf("response = %#v, want allow policy_allowed", resp)
	}
	if resp.Decision == nil || resp.Decision.Policy != "allow-source-cidr" {
		t.Fatalf("decision = %#v, want allow-source-cidr", resp.Decision)
	}
}

func TestRuntimeManagerSimulateHonorsPolicyLevelAudit(t *testing.T) {
	manager := &runtimeManager{
		enforcement: proxy.NewEnforcementOverrideController(slog.New(slog.NewTextHandler(io.Discard, nil))),
	}
	manager.current.cfg = testRuntimeConfig()
	manager.current.identityResolver = fakeIdentityResolver{identity: &identity.Identity{
		Name:     "default/web",
		Source:   "kubernetes",
		Provider: "cluster-a",
		Labels: map[string]string{
			"app":                     "web",
			"kubernetes.io/namespace": "default",
		},
	}}
	engine, err := policy.NewEngine([]config.PolicyConfig{{
		Name:        "legacy-web",
		Enforcement: config.EnforcementAudit,
		Subjects:    runtimeTestKubernetesSubjects(),
		Egress: []config.EgressRuleConfig{{
			FQDN:  "example.com",
			Ports: []int{80},
			TLS:   config.TLSRuleConfig{Mode: "mitm"},
			HTTP: &config.HTTPRuleConfig{
				AllowedMethods: []string{"POST"},
				AllowedPaths:   []string{"/*"},
			},
		}},
	}})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	manager.current.policyEngine = engine

	resp, err := manager.Simulate(appmetrics.SimulationRequest{
		SourceIP: "10.0.0.10",
		FQDN:     "example.com",
		Port:     80,
		Protocol: "http",
		Method:   http.MethodGet,
		Path:     "/blocked",
	})
	if err != nil {
		t.Fatalf("Simulate() error = %v", err)
	}
	if resp.Action != "allow" || resp.Reason != "audit_policy_denied" {
		t.Fatalf("response = %#v, want allow audit_policy_denied", resp)
	}
	if resp.Decision == nil || resp.Decision.PolicyEnforcement != config.EnforcementAudit {
		t.Fatalf("decision = %#v, want policy enforcement audit", resp.Decision)
	}
}

func TestRuntimeSimulationReturnsProviderScopedDecision(t *testing.T) {
	manager := &runtimeManager{
		enforcement: proxy.NewEnforcementOverrideController(slog.New(slog.NewTextHandler(io.Discard, nil))),
	}
	manager.current.cfg = testRuntimeConfig()
	manager.current.identityResolver = identity.NewCompositeResolver([]identity.ProviderHandle{{
		Name: "cluster-b",
		Kind: "kubernetes",
		Resolver: fakeIdentityResolver{identity: &identity.Identity{
			Source:   "ec2",
			Provider: "stale-provider",
			Name:     "default/web",
			Labels: map[string]string{
				"kubernetes.io/namespace": "default",
				"app":                     "web",
			},
		}},
	}}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)

	engine, err := policy.NewEngine([]config.PolicyConfig{{
		Name: "allow-cluster-b",
		Subjects: config.PolicySubjectsConfig{
			Kubernetes: &config.KubernetesSubjectConfig{
				DiscoveryNames: []string{"cluster-b"},
				Namespaces:     []string{"default"},
				MatchLabels: map[string]string{
					"app": "web",
				},
			},
		},
		Egress: []config.EgressRuleConfig{{
			FQDN:  "example.com",
			Ports: []int{443},
			TLS:   config.TLSRuleConfig{Mode: "passthrough"},
		}},
	}})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	manager.current.policyEngine = engine

	resp, err := manager.Simulate(appmetrics.SimulationRequest{
		SourceIP: "10.0.0.10",
		FQDN:     "example.com",
		Port:     443,
		Protocol: "connect",
	})
	if err != nil {
		t.Fatalf("Simulate() error = %v", err)
	}
	if resp.Identity == nil {
		t.Fatal("identity = nil, want bound identity")
	}
	if resp.Identity.Provider != "cluster-b" || resp.Identity.Source != "kubernetes" || resp.Identity.Kind != "kubernetes" {
		t.Fatalf("identity = %#v, want authoritative provider/source/kind", resp.Identity)
	}
	if resp.Action != "allow" || resp.Reason != "policy_allowed" {
		t.Fatalf("response = %#v, want allow policy_allowed", resp)
	}
	if resp.Decision == nil || resp.Decision.Policy != "allow-cluster-b" {
		t.Fatalf("decision = %#v, want allow-cluster-b", resp.Decision)
	}
}

func TestBuildIdentityResolverUsesHealthyEC2Provider(t *testing.T) {
	restoreKubernetes := newKubernetesRuntimeProvider
	restoreEC2 := newEC2RuntimeProvider
	t.Cleanup(func() {
		newKubernetesRuntimeProvider = restoreKubernetes
		newEC2RuntimeProvider = restoreEC2
	})

	newKubernetesRuntimeProvider = func(cfg config.KubernetesDiscoveryConfig, logger *slog.Logger) (identity.RuntimeProvider, error) {
		t.Fatalf("unexpected kubernetes provider build for %q", cfg.Name)
		return identity.RuntimeProvider{}, nil
	}
	newEC2RuntimeProvider = func(cfg config.EC2DiscoveryConfig, logger *slog.Logger) (identity.RuntimeProvider, error) {
		if cfg.Name != "production-ec2" {
			t.Fatalf("unexpected provider %q", cfg.Name)
		}
		return identity.RuntimeProvider{
			Name: "production-ec2",
			Kind: "ec2",
			Provider: fakeStartableResolver{
				identity: &identity.Identity{Name: "i-abc123"},
			},
		}, nil
	}

	reg := prometheus.NewRegistry()
	m := appmetrics.New(reg)
	resolver, err := buildIdentityResolver(context.Background(), config.DiscoveryConfig{
		EC2: []config.EC2DiscoveryConfig{{
			Name:   "production-ec2",
			Region: "eu-central-1",
		}},
	}, slog.New(slog.NewTextHandler(io.Discard, nil)), m)
	if err != nil {
		t.Fatalf("buildIdentityResolver() error = %v", err)
	}

	id, err := resolver.Resolve(net.ParseIP("10.0.0.10"))
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if id == nil || id.Name != "i-abc123" {
		t.Fatalf("Resolve() identity = %#v, want i-abc123", id)
	}
	if got := counterValue(t, reg, "aegis_discovery_provider_starts_total", map[string]string{"provider": "production-ec2", "kind": "ec2"}); got != 1 {
		t.Fatalf("start counter = %v, want 1", got)
	}
}

func serveReloadableHandler(t *testing.T, handler http.Handler) string {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)

	return resp.Body.String()
}

func writeRuntimeConfig(t *testing.T, contents string) string {
	t.Helper()

	dir := t.TempDir()
	path := dir + "/aegis.yaml"
	writeRuntimeConfigAt(t, path, contents)
	return path
}

func writeRuntimeConfigAt(t *testing.T, path string, contents string) {
	t.Helper()

	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
}

func runtimeConfigYAML(policyName string, proxyListen string, metricsListen string, proxyProtocol bool, proxyProtocolTimeout string) string {
	proxyProtocolBlock := ""
	if proxyProtocol {
		proxyProtocolBlock = "  proxyProtocol:\n    enabled: true\n"
		if proxyProtocolTimeout != "" {
			proxyProtocolBlock += "    headerTimeout: " + proxyProtocolTimeout + "\n"
		}
	}

	return "proxy:\n" +
		"  listen: \"" + proxyListen + "\"\n" +
		proxyProtocolBlock +
		"metrics:\n" +
		"  listen: \"" + metricsListen + "\"\n" +
		"dns:\n" +
		"  cache_ttl: 30s\n" +
		"  timeout: 5s\n" +
		"  servers: []\n" +
		"discovery:\n" +
		"  kubernetes:\n" +
		"    - name: cluster-a\n" +
		"      auth:\n" +
		"        provider: inCluster\n" +
		"policies:\n" +
		"  - name: " + policyName + "\n" +
		"    subjects:\n" +
		"      kubernetes:\n" +
		"        discoveryNames: [\"cluster-a\"]\n" +
		"        namespaces: [\"default\"]\n" +
		"        matchLabels:\n" +
		"          app: web\n" +
		"    egress:\n" +
		"      - fqdn: \"example.com\"\n" +
		"        ports: [80]\n" +
		"        tls:\n" +
		"          mode: mitm\n" +
		"        http:\n" +
		"          allowedMethods: [\"GET\"]\n" +
		"          allowedPaths: [\"/*\"]\n"
}

func runtimeConfigYAMLWithCA(policyName string, proxyListen string, metricsListen string, certFile string, keyFile string) string {
	return "proxy:\n" +
		"  listen: \"" + proxyListen + "\"\n" +
		"  ca:\n" +
		"    certFile: \"" + certFile + "\"\n" +
		"    keyFile: \"" + keyFile + "\"\n" +
		"metrics:\n" +
		"  listen: \"" + metricsListen + "\"\n" +
		"dns:\n" +
		"  cache_ttl: 30s\n" +
		"  timeout: 5s\n" +
		"  servers: []\n" +
		"discovery:\n" +
		"  kubernetes:\n" +
		"    - name: cluster-a\n" +
		"      auth:\n" +
		"        provider: inCluster\n" +
		"policies:\n" +
		"  - name: " + policyName + "\n" +
		"    subjects:\n" +
		"      kubernetes:\n" +
		"        discoveryNames: [\"cluster-a\"]\n" +
		"        namespaces: [\"default\"]\n" +
		"        matchLabels:\n" +
		"          app: web\n" +
		"    egress:\n" +
		"      - fqdn: \"example.com\"\n" +
		"        ports: [443]\n" +
		"        tls:\n" +
		"          mode: mitm\n" +
		"        http:\n" +
		"          allowedMethods: [\"GET\"]\n" +
		"          allowedPaths: [\"/*\"]\n"
}

func runtimeConfigYAMLWithAdditionalCAs(policyName string, proxyListen string, metricsListen string, certFile string, keyFile string, additional [][2]string) string {
	yaml := "proxy:\n" +
		"  listen: \"" + proxyListen + "\"\n" +
		"  ca:\n" +
		"    certFile: \"" + certFile + "\"\n" +
		"    keyFile: \"" + keyFile + "\"\n"
	if len(additional) > 0 {
		yaml += "    additional:\n"
		for _, pair := range additional {
			yaml += "      - certFile: \"" + pair[0] + "\"\n" +
				"        keyFile: \"" + pair[1] + "\"\n"
		}
	}
	yaml += "metrics:\n" +
		"  listen: \"" + metricsListen + "\"\n" +
		"dns:\n" +
		"  cache_ttl: 30s\n" +
		"  timeout: 5s\n" +
		"  servers: []\n" +
		"discovery:\n" +
		"  kubernetes:\n" +
		"    - name: cluster-a\n" +
		"      auth:\n" +
		"        provider: inCluster\n" +
		"policies:\n" +
		"  - name: " + policyName + "\n" +
		"    subjects:\n" +
		"      kubernetes:\n" +
		"        discoveryNames: [\"cluster-a\"]\n" +
		"        namespaces: [\"default\"]\n" +
		"        matchLabels:\n" +
		"          app: web\n" +
		"    egress:\n" +
		"      - fqdn: \"example.com\"\n" +
		"        ports: [443]\n" +
		"        tls:\n" +
		"          mode: mitm\n" +
		"        http:\n" +
		"          allowedMethods: [\"GET\"]\n" +
		"          allowedPaths: [\"/*\"]\n"
	return yaml
}

func testRuntimeConfig() config.Config {
	return config.Config{
		Proxy: config.ProxyConfig{
			Listen: ":3128",
		},
		Metrics: config.MetricsConfig{
			Listen: ":9090",
		},
		DNS: config.DNSConfig{
			CacheTTL: 30 * time.Second,
			Timeout:  5 * time.Second,
		},
		Shutdown: config.ShutdownConfig{
			GracePeriod: 10 * time.Second,
		},
		Discovery: runtimeTestKubernetesDiscovery(),
		Policies: []config.PolicyConfig{{
			Name:     "allow-example",
			Subjects: runtimeTestKubernetesSubjects(),
			Egress: []config.EgressRuleConfig{{
				FQDN:  "example.com",
				Ports: []int{80},
				TLS:   config.TLSRuleConfig{Mode: "mitm"},
				HTTP: &config.HTTPRuleConfig{
					AllowedMethods: []string{"GET"},
					AllowedPaths:   []string{"/*"},
				},
			}},
		}},
	}
}

func testRuntimeCIDRPolicy(name string, cidr string, fqdn string) config.PolicyConfig {
	return config.PolicyConfig{
		Name:        name,
		Enforcement: config.EnforcementEnforce,
		Subjects: config.PolicySubjectsConfig{
			CIDRs: []string{cidr},
		},
		Egress: []config.EgressRuleConfig{{
			FQDN:  fqdn,
			Ports: []int{443},
			TLS: config.TLSRuleConfig{
				Mode: "passthrough",
			},
		}},
	}
}

func policyNames(policies []config.PolicyConfig) []string {
	names := make([]string, 0, len(policies))
	for _, cfg := range policies {
		names = append(names, cfg.Name)
	}
	return names
}

func writeTestCAFiles(t *testing.T, commonName string) (string, string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}

	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey() error = %v", err)
	}

	dir := t.TempDir()
	certFile := dir + "/ca.crt"
	keyFile := dir + "/ca.key"

	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatalf("WriteFile(cert) error = %v", err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}), 0o600); err != nil {
		t.Fatalf("WriteFile(key) error = %v", err)
	}

	return certFile, keyFile
}

func TestBuildIdentityResolverPrefersKubernetesBeforeEC2(t *testing.T) {
	restoreKubernetes := newKubernetesRuntimeProvider
	restoreEC2 := newEC2RuntimeProvider
	t.Cleanup(func() {
		newKubernetesRuntimeProvider = restoreKubernetes
		newEC2RuntimeProvider = restoreEC2
	})

	newKubernetesRuntimeProvider = func(cfg config.KubernetesDiscoveryConfig, logger *slog.Logger) (identity.RuntimeProvider, error) {
		return identity.RuntimeProvider{
			Name: "cluster-a",
			Kind: "kubernetes",
			Provider: fakeStartableResolver{
				identity: &identity.Identity{Name: "default/api"},
			},
		}, nil
	}
	newEC2RuntimeProvider = func(cfg config.EC2DiscoveryConfig, logger *slog.Logger) (identity.RuntimeProvider, error) {
		return identity.RuntimeProvider{
			Name: "production-ec2",
			Kind: "ec2",
			Provider: fakeStartableResolver{
				identity: &identity.Identity{Name: "i-abc123"},
			},
		}, nil
	}

	reg := prometheus.NewRegistry()
	m := appmetrics.New(reg)
	resolver, err := buildIdentityResolver(context.Background(), config.DiscoveryConfig{
		Kubernetes: []config.KubernetesDiscoveryConfig{{Name: "cluster-a"}},
		EC2:        []config.EC2DiscoveryConfig{{Name: "production-ec2", Region: "eu-central-1"}},
	}, slog.New(slog.NewTextHandler(io.Discard, nil)), m)
	if err != nil {
		t.Fatalf("buildIdentityResolver() error = %v", err)
	}

	id, err := resolver.Resolve(net.ParseIP("10.0.0.10"))
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if id == nil || id.Name != "default/api" {
		t.Fatalf("Resolve() identity = %#v, want default/api", id)
	}
	if got := counterValue(t, reg, "aegis_identity_overlaps_total", map[string]string{
		"winner_provider": "cluster-a",
		"winner_kind":     "kubernetes",
		"shadow_provider": "production-ec2",
		"shadow_kind":     "ec2",
	}); got != 1 {
		t.Fatalf("overlap metric = %v, want 1", got)
	}
}

type fakeStartableResolver struct {
	identity *identity.Identity
	startErr error
	startFn  func(context.Context, time.Duration) error
}

func (r fakeStartableResolver) Start(ctx context.Context, startupTimeout time.Duration) error {
	if r.startFn != nil {
		return r.startFn(ctx, startupTimeout)
	}
	return r.startErr
}

func (r fakeStartableResolver) Resolve(net.IP) (*identity.Identity, error) {
	return r.identity, nil
}

type fakeIdentityResolver struct {
	identity *identity.Identity
	err      error
}

func (r fakeIdentityResolver) Resolve(net.IP) (*identity.Identity, error) {
	return r.identity, r.err
}

type fakeDumpResolver struct {
	entries []identity.DumpEntry
}

func (r fakeDumpResolver) Resolve(net.IP) (*identity.Identity, error) {
	return nil, nil
}

func (r fakeDumpResolver) IdentityDump() []identity.DumpEntry {
	return r.entries
}

type fakeHandlerProvider struct {
	handler http.Handler
}

func (p fakeHandlerProvider) Handler() http.Handler {
	return p.handler
}

type fakePolicyDiscoveryRunner struct {
	apply      func(string, policydiscovery.Snapshot) error
	sources    []config.PolicyDiscoverySourceConfig
	startFn    func(*fakePolicyDiscoveryRunner) error
	startCalls int
	closeCalls int
}

func (r *fakePolicyDiscoveryRunner) Start() error {
	r.startCalls++
	if r.startFn != nil {
		return r.startFn(r)
	}
	return nil
}

func (r *fakePolicyDiscoveryRunner) Close() error {
	r.closeCalls++
	return nil
}

func counterValue(t *testing.T, reg *prometheus.Registry, name string, labels map[string]string) float64 {
	t.Helper()

	metric := findMetric(t, reg, name, labels)
	if metric == nil {
		return 0
	}
	if metric.Counter == nil {
		t.Fatalf("metric %q is not a counter", name)
	}

	return metric.Counter.GetValue()
}

func gaugeValue(t *testing.T, reg *prometheus.Registry, name string) float64 {
	t.Helper()

	metric := mustFindMetric(t, reg, name, nil)
	if metric.Gauge == nil {
		t.Fatalf("metric %q is not a gauge", name)
	}

	return metric.Gauge.GetValue()
}

func mustFindMetric(t *testing.T, reg *prometheus.Registry, name string, labels map[string]string) *dto.Metric {
	t.Helper()

	metric := findMetric(t, reg, name, labels)
	if metric == nil {
		t.Fatalf("metric %q with labels %#v not found", name, labels)
	}
	return metric
}

func findMetric(t *testing.T, reg *prometheus.Registry, name string, labels map[string]string) *dto.Metric {
	t.Helper()

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v", err)
	}

	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.GetMetric() {
			if hasLabels(metric, labels) {
				return metric
			}
		}
	}

	return nil
}

func metricExists(reg *prometheus.Registry, name string, labels map[string]string) bool {
	families, err := reg.Gather()
	if err != nil {
		return false
	}

	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.GetMetric() {
			if hasLabels(metric, labels) {
				return true
			}
		}
	}

	return false
}

func hasLabels(metric *dto.Metric, want map[string]string) bool {
	if len(want) == 0 {
		return len(metric.GetLabel()) == 0
	}
	if len(metric.GetLabel()) != len(want) {
		return false
	}

	for _, pair := range metric.GetLabel() {
		if want[pair.GetName()] != pair.GetValue() {
			return false
		}
	}

	return true
}

func generateTestCA(t *testing.T) ([]byte, []byte) {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test-ca",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey() error = %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	return certPEM, keyPEM
}
