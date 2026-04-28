package policydiscovery

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/moolen/aegis/internal/config"
)

const (
	apiVersion      = "aegis.io/v1alpha1"
	kindProxyPolicy = "ProxyPolicy"
)

type Metadata struct {
	Name string `yaml:"name"`
}

type ProxyPolicy struct {
	APIVersion string          `yaml:"apiVersion"`
	Kind       string          `yaml:"kind"`
	Metadata   Metadata        `yaml:"metadata"`
	Spec       ProxyPolicySpec `yaml:"spec"`
}

type ProxyPolicySpec struct {
	Enforcement string                  `yaml:"enforcement"`
	Bypass      bool                    `yaml:"bypass"`
	Subjects    ProxyPolicySubjectsSpec `yaml:"subjects"`
	Egress      []ProxyPolicyEgressRule `yaml:"egress"`
}

type ProxyPolicySubjectsSpec struct {
	Kubernetes *ProxyPolicyKubernetesSubjects `yaml:"kubernetes,omitempty"`
	EC2        *ProxyPolicyEC2Subjects        `yaml:"ec2,omitempty"`
	CIDRs      []string                       `yaml:"cidrs,omitempty"`
}

type ProxyPolicyKubernetesSubjects struct {
	DiscoveryNames []string          `yaml:"discoveryNames"`
	Namespaces     []string          `yaml:"namespaces"`
	MatchLabels    map[string]string `yaml:"matchLabels"`
}

type ProxyPolicyEC2Subjects struct {
	DiscoveryNames []string `yaml:"discoveryNames"`
}

type ProxyPolicyEgressRule struct {
	FQDN  string               `yaml:"fqdn"`
	Ports []int                `yaml:"ports"`
	TLS   ProxyPolicyTLSRule   `yaml:"tls"`
	HTTP  *ProxyPolicyHTTPRule `yaml:"http,omitempty"`
}

type ProxyPolicyTLSRule struct {
	Mode string `yaml:"mode"`
}

type ProxyPolicyHTTPRule struct {
	AllowedMethods []string `yaml:"allowedMethods"`
	AllowedPaths   []string `yaml:"allowedPaths"`
}

func (p ProxyPolicy) Normalize() (config.PolicyConfig, error) {
	name := strings.TrimSpace(p.Metadata.Name)
	if name == "" {
		return config.PolicyConfig{}, fmt.Errorf("metadata.name is required")
	}

	policy := config.PolicyConfig{
		Name:        name,
		Enforcement: config.NormalizeEnforcementMode(p.Spec.Enforcement),
		Bypass:      p.Spec.Bypass,
		Subjects:    normalizePolicySubjects(p.Spec.Subjects),
		Egress:      normalizeEgressRules(p.Spec.Egress),
	}

	if policy.Subjects.Kubernetes != nil {
		for i := range policy.Subjects.Kubernetes.DiscoveryNames {
			policy.Subjects.Kubernetes.DiscoveryNames[i] = strings.TrimSpace(policy.Subjects.Kubernetes.DiscoveryNames[i])
		}
		if len(policy.IdentitySelector.MatchLabels) == 0 {
			policy.IdentitySelector.MatchLabels = cloneStringMap(policy.Subjects.Kubernetes.MatchLabels)
		}
	}
	if policy.Subjects.EC2 != nil {
		for i := range policy.Subjects.EC2.DiscoveryNames {
			policy.Subjects.EC2.DiscoveryNames[i] = strings.TrimSpace(policy.Subjects.EC2.DiscoveryNames[i])
		}
	}
	for i := range policy.Subjects.CIDRs {
		normalizedCIDR, err := normalizeCIDR(policy.Subjects.CIDRs[i])
		if err != nil {
			return config.PolicyConfig{}, fmt.Errorf("subjects.cidrs[%d]: %w", i, err)
		}
		policy.Subjects.CIDRs[i] = normalizedCIDR
	}

	return policy, nil
}

func normalizeCIDR(value string) (string, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "", fmt.Errorf("must not be empty")
	}
	prefix, err := netip.ParsePrefix(trimmed)
	if err != nil {
		return "", err
	}
	return prefix.Masked().String(), nil
}

func cloneStringMap(src map[string]string) map[string]string {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[string]string, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func normalizePolicySubjects(src ProxyPolicySubjectsSpec) config.PolicySubjectsConfig {
	dst := config.PolicySubjectsConfig{
		CIDRs: append([]string(nil), src.CIDRs...),
	}
	if src.Kubernetes != nil {
		dst.Kubernetes = &config.KubernetesSubjectConfig{
			DiscoveryNames: append([]string(nil), src.Kubernetes.DiscoveryNames...),
			Namespaces:     append([]string(nil), src.Kubernetes.Namespaces...),
			MatchLabels:    cloneStringMap(src.Kubernetes.MatchLabels),
		}
	}
	if src.EC2 != nil {
		dst.EC2 = &config.EC2SubjectConfig{
			DiscoveryNames: append([]string(nil), src.EC2.DiscoveryNames...),
		}
	}
	return dst
}

func normalizeEgressRules(src []ProxyPolicyEgressRule) []config.EgressRuleConfig {
	if src == nil {
		return nil
	}
	dst := make([]config.EgressRuleConfig, len(src))
	for i := range src {
		dst[i] = config.EgressRuleConfig{
			FQDN:  src[i].FQDN,
			Ports: append([]int(nil), src[i].Ports...),
			TLS: config.TLSRuleConfig{
				Mode: src[i].TLS.Mode,
			},
		}
		if src[i].HTTP != nil {
			dst[i].HTTP = &config.HTTPRuleConfig{
				AllowedMethods: append([]string(nil), src[i].HTTP.AllowedMethods...),
				AllowedPaths:   append([]string(nil), src[i].HTTP.AllowedPaths...),
			}
		}
	}
	return dst
}
