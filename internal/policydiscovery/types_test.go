package policydiscovery

import (
	"reflect"
	"testing"

	"github.com/moolen/aegis/internal/config"
)

func TestProxyPolicyNormalizeSetsNameAndHydratesCompatibilityFields(t *testing.T) {
	resource := ProxyPolicy{
		APIVersion: apiVersion,
		Kind:       kindProxyPolicy,
		Metadata: Metadata{
			Name: "allow-web",
		},
		Spec: config.PolicyConfig{
			Enforcement: "audit",
			Subjects: config.PolicySubjectsConfig{
				Kubernetes: &config.KubernetesSubjectConfig{
					DiscoveryNames: []string{" cluster-a "},
					Namespaces:     []string{"default"},
					MatchLabels: map[string]string{
						"app": "web",
					},
				},
				CIDRs: []string{" 10.20.0.1/16 "},
			},
			Egress: []config.EgressRuleConfig{
				{
					FQDN:  "example.com",
					Ports: []int{443},
					TLS: config.TLSRuleConfig{
						Mode: "passthrough",
					},
				},
			},
		},
	}

	got, err := resource.Normalize()
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}

	want := config.PolicyConfig{
		Name:        "allow-web",
		Enforcement: "audit",
		Subjects: config.PolicySubjectsConfig{
			Kubernetes: &config.KubernetesSubjectConfig{
				DiscoveryNames: []string{"cluster-a"},
				Namespaces:     []string{"default"},
				MatchLabels: map[string]string{
					"app": "web",
				},
			},
			CIDRs: []string{"10.20.0.0/16"},
		},
		IdentitySelector: config.IdentitySelectorConfig{
			MatchLabels: map[string]string{
				"app": "web",
			},
		},
		Egress: []config.EgressRuleConfig{
			{
				FQDN:  "example.com",
				Ports: []int{443},
				TLS: config.TLSRuleConfig{
					Mode: "passthrough",
				},
			},
		},
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Normalize() = %#v, want %#v", got, want)
	}
}
