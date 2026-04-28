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

func TestMergePoliciesKeepsStaticFirstAndOrdersRemoteDeterministically(t *testing.T) {
	staticPolicies := []config.PolicyConfig{
		testPolicyConfig("static-first", "10.0.0.0/24", "static.example.com"),
	}
	snapshots := map[string]Snapshot{
		"source-b": {
			Source: config.PolicyDiscoverySourceConfig{Name: "source-b"},
			Policies: []DiscoveredPolicy{
				{
					SourceName: "source-b",
					Object:     ObjectRef{URI: "s3://bucket/z.yaml"},
					Policy:     testPolicyConfig("remote-z", "10.3.0.0/24", "z.example.com"),
				},
			},
		},
		"source-a": {
			Source: config.PolicyDiscoverySourceConfig{Name: "source-a"},
			Policies: []DiscoveredPolicy{
				{
					SourceName: "source-a",
					Object:     ObjectRef{URI: "s3://bucket/b.yaml"},
					Policy:     testPolicyConfig("remote-b", "10.2.0.0/24", "b.example.com"),
				},
				{
					SourceName: "source-a",
					Object:     ObjectRef{URI: "s3://bucket/a.yaml"},
					Policy:     testPolicyConfig("remote-a", "10.1.0.0/24", "a.example.com"),
				},
			},
		},
	}

	merged, err := MergePolicies(staticPolicies, snapshots)
	if err != nil {
		t.Fatalf("MergePolicies() error = %v", err)
	}

	want := []config.PolicyConfig{
		testPolicyConfig("static-first", "10.0.0.0/24", "static.example.com"),
		testPolicyConfig("remote-a", "10.1.0.0/24", "a.example.com"),
		testPolicyConfig("remote-b", "10.2.0.0/24", "b.example.com"),
		testPolicyConfig("remote-z", "10.3.0.0/24", "z.example.com"),
	}
	if !reflect.DeepEqual(merged, want) {
		t.Fatalf("MergePolicies() = %#v, want %#v", merged, want)
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

	replaced := ReplaceSourceSnapshot(current, "prod-aws", Snapshot{
		Source: config.PolicyDiscoverySourceConfig{Name: "different-name"},
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
	if _, exists := replaced["different-name"]; exists {
		t.Fatal("replacement should use explicit source key, not snapshot payload name")
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
