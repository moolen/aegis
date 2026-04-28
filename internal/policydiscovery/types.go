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
	APIVersion string              `yaml:"apiVersion"`
	Kind       string              `yaml:"kind"`
	Metadata   Metadata            `yaml:"metadata"`
	Spec       config.PolicyConfig `yaml:"spec"`
}

func (p ProxyPolicy) Normalize() (config.PolicyConfig, error) {
	name := strings.TrimSpace(p.Metadata.Name)
	if name == "" {
		return config.PolicyConfig{}, fmt.Errorf("metadata.name is required")
	}

	policy := clonePolicyConfig(p.Spec)
	policy.Name = name
	policy.Enforcement = config.NormalizeEnforcementMode(policy.Enforcement)

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

func clonePolicyConfig(src config.PolicyConfig) config.PolicyConfig {
	dst := src
	dst.Subjects = clonePolicySubjectsConfig(src.Subjects)
	dst.IdentitySelector.MatchLabels = cloneStringMap(src.IdentitySelector.MatchLabels)
	dst.Egress = cloneEgressRules(src.Egress)
	if src.LegacyIdentitySelector != nil {
		legacy := *src.LegacyIdentitySelector
		legacy.MatchLabels = cloneStringMap(src.LegacyIdentitySelector.MatchLabels)
		dst.LegacyIdentitySelector = &legacy
	}
	return dst
}

func clonePolicySubjectsConfig(src config.PolicySubjectsConfig) config.PolicySubjectsConfig {
	dst := src
	if src.Kubernetes != nil {
		kubernetes := *src.Kubernetes
		kubernetes.DiscoveryNames = append([]string(nil), src.Kubernetes.DiscoveryNames...)
		kubernetes.Namespaces = append([]string(nil), src.Kubernetes.Namespaces...)
		kubernetes.MatchLabels = cloneStringMap(src.Kubernetes.MatchLabels)
		dst.Kubernetes = &kubernetes
	}
	if src.EC2 != nil {
		ec2 := *src.EC2
		ec2.DiscoveryNames = append([]string(nil), src.EC2.DiscoveryNames...)
		dst.EC2 = &ec2
	}
	dst.CIDRs = append([]string(nil), src.CIDRs...)
	return dst
}

func cloneEgressRules(src []config.EgressRuleConfig) []config.EgressRuleConfig {
	if src == nil {
		return nil
	}
	dst := make([]config.EgressRuleConfig, len(src))
	for i := range src {
		dst[i] = src[i]
		dst[i].Ports = append([]int(nil), src[i].Ports...)
		if src[i].HTTP != nil {
			httpRule := *src[i].HTTP
			httpRule.AllowedMethods = append([]string(nil), src[i].HTTP.AllowedMethods...)
			httpRule.AllowedPaths = append([]string(nil), src[i].HTTP.AllowedPaths...)
			dst[i].HTTP = &httpRule
		}
	}
	return dst
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
