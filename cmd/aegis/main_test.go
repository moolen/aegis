package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/moolen/aegis/internal/config"
	aegisruntime "github.com/moolen/aegis/internal/runtime"
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

func TestRunServeInvokesRuntimeWithParsedConfigPath(t *testing.T) {
	previousRunRuntime := runRuntime
	t.Cleanup(func() {
		runRuntime = previousRunRuntime
	})

	var gotOptions aegisruntime.Options
	runRuntime = func(_ context.Context, options aegisruntime.Options) error {
		gotOptions = options
		return nil
	}

	if got := runServe([]string{"-config", "testdata/custom.yaml"}); got != 0 {
		t.Fatalf("runServe() = %d, want 0", got)
	}
	if gotOptions.ConfigPath != "testdata/custom.yaml" {
		t.Fatalf("runRuntime config path = %q, want %q", gotOptions.ConfigPath, "testdata/custom.yaml")
	}
}

func TestRunServeReturnsExitCodeOneWhenRuntimeFails(t *testing.T) {
	previousRunRuntime := runRuntime
	t.Cleanup(func() {
		runRuntime = previousRunRuntime
	})

	var gotOptions aegisruntime.Options
	runRuntime = func(_ context.Context, options aegisruntime.Options) error {
		gotOptions = options
		return errors.New("boom")
	}

	if got := runServe([]string{"-config", "testdata/broken.yaml"}); got != 1 {
		t.Fatalf("runServe() = %d, want 1", got)
	}
	if gotOptions.ConfigPath != "testdata/broken.yaml" {
		t.Fatalf("runRuntime config path = %q, want %q", gotOptions.ConfigPath, "testdata/broken.yaml")
	}
}
