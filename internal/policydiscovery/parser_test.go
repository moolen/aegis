package policydiscovery

import (
	"reflect"
	"strings"
	"testing"

	"github.com/moolen/aegis/internal/config"
)

func TestParseSingleProxyPolicyDocument(t *testing.T) {
	policies, err := Parse(strings.NewReader(`
apiVersion: aegis.io/v1alpha1
kind: ProxyPolicy
metadata:
  name: allow-web
spec:
  enforcement: audit
  subjects:
    kubernetes:
      discoveryNames: ["cluster-a"]
      namespaces: ["default"]
      matchLabels:
        app: web
  egress:
    - fqdn: example.com
      ports: [443]
      tls:
        mode: passthrough
`))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	want := []config.PolicyConfig{
		{
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
		},
	}

	if !reflect.DeepEqual(policies, want) {
		t.Fatalf("Parse() = %#v, want %#v", policies, want)
	}
}

func TestParseMultiDocumentYAMLFile(t *testing.T) {
	policies, err := Parse(strings.NewReader(`
apiVersion: aegis.io/v1alpha1
kind: ProxyPolicy
metadata:
  name: allow-web
spec:
  subjects:
    cidrs: ["10.20.0.0/16"]
  egress:
    - fqdn: example.com
      ports: [443]
      tls:
        mode: passthrough
---
---
apiVersion: aegis.io/v1alpha1
kind: ProxyPolicy
metadata:
  name: allow-admin
spec:
  subjects:
    cidrs: ["192.168.1.10/24"]
  egress:
    - fqdn: internal.example.com
      ports: [8443]
      tls:
        mode: mitm
`))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	want := []config.PolicyConfig{
		{
			Name:        "allow-web",
			Enforcement: "enforce",
			Subjects: config.PolicySubjectsConfig{
				CIDRs: []string{"10.20.0.0/16"},
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
		{
			Name:        "allow-admin",
			Enforcement: "enforce",
			Subjects: config.PolicySubjectsConfig{
				CIDRs: []string{"192.168.1.0/24"},
			},
			Egress: []config.EgressRuleConfig{
				{
					FQDN:  "internal.example.com",
					Ports: []int{8443},
					TLS: config.TLSRuleConfig{
						Mode: "mitm",
					},
				},
			},
		},
	}

	if !reflect.DeepEqual(policies, want) {
		t.Fatalf("Parse() = %#v, want %#v", policies, want)
	}
}

func TestParseRejectsNonProxyPolicyDocument(t *testing.T) {
	_, err := Parse(strings.NewReader(`
apiVersion: v1
kind: ConfigMap
metadata:
  name: not-a-policy
data:
  key: value
`))
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "ProxyPolicy") {
		t.Fatalf("error = %v, want ProxyPolicy validation failure", err)
	}
}

func TestParseRejectsSpecNameField(t *testing.T) {
	_, err := Parse(strings.NewReader(`
apiVersion: aegis.io/v1alpha1
kind: ProxyPolicy
metadata:
  name: allow-web
spec:
  name: should-not-be-accepted
  subjects:
    cidrs: ["10.20.0.0/16"]
  egress:
    - fqdn: example.com
      ports: [443]
      tls:
        mode: passthrough
`))
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "field name not found") || !strings.Contains(err.Error(), "ProxyPolicySpec") || !strings.Contains(err.Error(), "name") {
		t.Fatalf("error = %v, want strict spec.name rejection", err)
	}
}
