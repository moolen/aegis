package policydiscovery

import (
	"fmt"
	"sort"

	"github.com/moolen/aegis/internal/config"
	"github.com/moolen/aegis/internal/policy"
)

func MergePolicies(staticPolicies []config.PolicyConfig, snapshots map[string]Snapshot) ([]config.PolicyConfig, error) {
	merged := make([]config.PolicyConfig, 0, len(staticPolicies)+countDiscoveredPolicies(snapshots))
	names := make(map[string]string, len(staticPolicies)+countDiscoveredPolicies(snapshots))

	for _, cfg := range staticPolicies {
		if err := addMergedPolicy(&merged, names, cfg, "static config"); err != nil {
			return nil, err
		}
	}

	for _, sourceName := range sortedSnapshotSourceNames(snapshots) {
		snapshot := snapshots[sourceName]
		for _, discovered := range sortedDiscoveredPolicies(snapshot.Policies) {
			origin := fmt.Sprintf("remote source %q", snapshotSourceName(snapshot, sourceName))
			if err := addMergedPolicy(&merged, names, discovered.Policy, origin); err != nil {
				return nil, err
			}
		}
	}

	return merged, nil
}

func ReplaceSourceSnapshot(current map[string]Snapshot, sourceName string, snapshot Snapshot) map[string]Snapshot {
	next := make(map[string]Snapshot, len(current)+1)
	for sourceName, existing := range current {
		next[sourceName] = existing
	}
	next[sourceName] = snapshot
	return next
}

func CompileMergedEngine(staticPolicies []config.PolicyConfig, snapshots map[string]Snapshot) (*policy.Engine, []config.PolicyConfig, error) {
	merged, err := MergePolicies(staticPolicies, snapshots)
	if err != nil {
		return nil, nil, err
	}

	engine, err := policy.NewEngine(merged)
	if err != nil {
		return nil, nil, err
	}

	return engine, merged, nil
}

func addMergedPolicy(merged *[]config.PolicyConfig, names map[string]string, cfg config.PolicyConfig, origin string) error {
	if previousOrigin, exists := names[cfg.Name]; exists {
		return fmt.Errorf("duplicate policy name %q across %s and %s", cfg.Name, previousOrigin, origin)
	}
	names[cfg.Name] = origin
	*merged = append(*merged, clonePolicyConfig(cfg))
	return nil
}

func countDiscoveredPolicies(snapshots map[string]Snapshot) int {
	total := 0
	for _, snapshot := range snapshots {
		total += len(snapshot.Policies)
	}
	return total
}

func sortedSnapshotSourceNames(snapshots map[string]Snapshot) []string {
	names := make([]string, 0, len(snapshots))
	for sourceName := range snapshots {
		names = append(names, sourceName)
	}
	sort.Strings(names)
	return names
}

func sortedDiscoveredPolicies(policies []DiscoveredPolicy) []DiscoveredPolicy {
	if len(policies) == 0 {
		return nil
	}
	sorted := append([]DiscoveredPolicy(nil), policies...)
	sort.Slice(sorted, func(i, j int) bool {
		left := sorted[i]
		right := sorted[j]
		if left.Object.URI != right.Object.URI {
			return left.Object.URI < right.Object.URI
		}
		if left.Policy.Name != right.Policy.Name {
			return left.Policy.Name < right.Policy.Name
		}
		if left.Object.Key != right.Object.Key {
			return left.Object.Key < right.Object.Key
		}
		return left.Object.Revision < right.Object.Revision
	})
	return sorted
}

func snapshotSourceName(snapshot Snapshot, fallback string) string {
	if snapshot.Source.Name != "" {
		return snapshot.Source.Name
	}
	return fallback
}

func clonePolicyConfig(src config.PolicyConfig) config.PolicyConfig {
	dst := src
	dst.Subjects = clonePolicySubjectsConfig(src.Subjects)
	dst.Egress = cloneEgressRules(src.Egress)
	if src.LegacyIdentitySelector != nil {
		legacy := *src.LegacyIdentitySelector
		legacy.MatchLabels = cloneStringMap(src.LegacyIdentitySelector.MatchLabels)
		dst.LegacyIdentitySelector = &legacy
	}
	dst.IdentitySelector.MatchLabels = cloneStringMap(src.IdentitySelector.MatchLabels)
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
