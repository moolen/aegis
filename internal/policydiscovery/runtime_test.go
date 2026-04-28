package policydiscovery

import (
	"reflect"
	"strings"
	"testing"

	"github.com/moolen/aegis/internal/config"
)

func TestCompileMergedEngineCombinesStaticAndRemotePolicies(t *testing.T) {
	staticPolicies := []config.PolicyConfig{
		testPolicyConfig("static-allow", "10.0.0.0/24", "static.example.com"),
	}
	snapshots := map[string]Snapshot{
		"prod-aws": {
			Source: config.PolicyDiscoverySourceConfig{Name: "prod-aws"},
			Policies: []DiscoveredPolicy{
				{
					SourceName: "prod-aws",
					Policy:     testPolicyConfig("remote-allow", "10.1.0.0/24", "remote.example.com"),
				},
			},
		},
	}

	engine, merged, err := CompileMergedEngine(staticPolicies, snapshots)
	if err != nil {
		t.Fatalf("CompileMergedEngine() error = %v", err)
	}
	if engine == nil {
		t.Fatal("CompileMergedEngine() engine = nil")
	}

	want := []config.PolicyConfig{
		testPolicyConfig("static-allow", "10.0.0.0/24", "static.example.com"),
		testPolicyConfig("remote-allow", "10.1.0.0/24", "remote.example.com"),
	}
	if !reflect.DeepEqual(merged, want) {
		t.Fatalf("CompileMergedEngine() merged = %#v, want %#v", merged, want)
	}
}

func TestMergePoliciesRejectsDuplicatePolicyNamesAcrossSources(t *testing.T) {
	staticPolicies := []config.PolicyConfig{
		testPolicyConfig("shared-name", "10.0.0.0/24", "static.example.com"),
	}
	snapshots := map[string]Snapshot{
		"prod-aws": {
			Source: config.PolicyDiscoverySourceConfig{Name: "prod-aws"},
			Policies: []DiscoveredPolicy{
				{
					SourceName: "prod-aws",
					Policy:     testPolicyConfig("shared-name", "10.1.0.0/24", "remote.example.com"),
				},
			},
		},
	}

	_, err := MergePolicies(staticPolicies, snapshots)
	if err == nil {
		t.Fatal("expected duplicate-name error")
	}
	if !strings.Contains(err.Error(), "shared-name") || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("error = %v, want duplicate shared-name error", err)
	}
}

func TestReplaceSourceSnapshotRemovesDeletedDocumentsFromActiveState(t *testing.T) {
	current := map[string]Snapshot{
		"prod-aws": {
			Source: config.PolicyDiscoverySourceConfig{Name: "prod-aws"},
			Policies: []DiscoveredPolicy{
				{
					SourceName: "prod-aws",
					Policy:     testPolicyConfig("remote-a", "10.1.0.0/24", "a.example.com"),
				},
				{
					SourceName: "prod-aws",
					Policy:     testPolicyConfig("remote-b", "10.2.0.0/24", "b.example.com"),
				},
			},
		},
	}

	replaced := ReplaceSourceSnapshot(current, Snapshot{
		Source: config.PolicyDiscoverySourceConfig{Name: "prod-aws"},
		Policies: []DiscoveredPolicy{
			{
				SourceName: "prod-aws",
				Policy:     testPolicyConfig("remote-a", "10.1.0.0/24", "a.example.com"),
			},
		},
	})

	merged, err := MergePolicies(nil, replaced)
	if err != nil {
		t.Fatalf("MergePolicies() error = %v", err)
	}

	want := []config.PolicyConfig{
		testPolicyConfig("remote-a", "10.1.0.0/24", "a.example.com"),
	}
	if !reflect.DeepEqual(merged, want) {
		t.Fatalf("merged policies = %#v, want %#v", merged, want)
	}
}

func testPolicyConfig(name string, cidr string, fqdn string) config.PolicyConfig {
	return config.PolicyConfig{
		Name:        name,
		Enforcement: "enforce",
		Subjects: config.PolicySubjectsConfig{
			CIDRs: []string{cidr},
		},
		Egress: []config.EgressRuleConfig{
			{
				FQDN:  fqdn,
				Ports: []int{443},
				TLS: config.TLSRuleConfig{
					Mode: "passthrough",
				},
			},
		},
	}
}
