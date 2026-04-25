package main

import (
	"strings"
	"testing"

	"github.com/moolen/aegis/internal/config"
)

func TestDiffConfigsDetectsPolicyAndModeChanges(t *testing.T) {
	current := testRuntimeConfig()
	next := testRuntimeConfig()
	next.Proxy.Enforcement = config.EnforcementAudit
	next.Proxy.UnknownIdentityPolicy = config.UnknownIdentityDeny
	next.Policies[0].Enforcement = config.EnforcementAudit
	next.Policies = append(next.Policies, config.PolicyConfig{
		Name: "allow-other",
		IdentitySelector: config.IdentitySelectorConfig{
			MatchLabels: map[string]string{"app": "other"},
		},
		Egress: []config.EgressRuleConfig{{
			FQDN:  "other.example.com",
			Ports: []int{443},
			TLS:   config.TLSRuleConfig{Mode: "passthrough"},
		}},
	})

	diff := strings.Join(diffConfigs(current, next), "\n")
	for _, want := range []string{
		"policy added: allow-other",
		"policy changed: allow-example",
		"proxy.enforcement: enforce -> audit",
		"proxy.unknownIdentityPolicy: allow -> deny",
	} {
		if !strings.Contains(diff, want) {
			t.Fatalf("diff output missing %q\n%s", want, diff)
		}
	}
}

func TestRunCLILeavesServeModeForFlagInvocation(t *testing.T) {
	if got := runCLI([]string{"-h"}); got != 2 {
		t.Fatalf("runCLI(-h) = %d, want 2", got)
	}
}
