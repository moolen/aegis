package policy

import (
	"net/http"
	"testing"

	"github.com/moolen/aegis/internal/config"
	"github.com/moolen/aegis/internal/identity"
)

func TestEvaluateHTTPOutcomeDeniesUnknownIdentityInEnforceMode(t *testing.T) {
	engine, err := NewEngine([]config.PolicyConfig{{
		Name:     "allow-web",
		Subjects: kubernetesSubjects([]string{"cluster-a"}, []string{"default"}, map[string]string{"app": "web"}),
		Egress: []config.EgressRuleConfig{{
			FQDN:  "example.com",
			Ports: []int{80},
			TLS:   config.TLSRuleConfig{Mode: "passthrough"},
		}},
	}})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	outcome := engine.EvaluateHTTPOutcome(EvaluateInput{
		Identity:              identity.Unknown(),
		SourceIP:              testSourceIP,
		FQDN:                  "example.com",
		Port:                  80,
		Method:                http.MethodGet,
		Path:                  "/",
		EnforcementMode:       config.EnforcementEnforce,
		UnknownIdentityPolicy: config.UnknownIdentityDeny,
	})

	if outcome.Action != "deny" {
		t.Fatalf("outcome.Action = %q, want %q", outcome.Action, "deny")
	}
	if outcome.Reason != "unknown_identity" {
		t.Fatalf("outcome.Reason = %q, want %q", outcome.Reason, "unknown_identity")
	}
	if outcome.Matched {
		t.Fatal("outcome.Matched = true, want false")
	}
	if outcome.Audit.Enabled {
		t.Fatal("outcome.Audit.Enabled = true, want false")
	}
}

func TestEvaluateHTTPOutcomeAuditsUnknownIdentityInAuditMode(t *testing.T) {
	engine, err := NewEngine([]config.PolicyConfig{{
		Name:     "allow-web",
		Subjects: kubernetesSubjects([]string{"cluster-a"}, []string{"default"}, map[string]string{"app": "web"}),
		Egress: []config.EgressRuleConfig{{
			FQDN:  "example.com",
			Ports: []int{80},
			TLS:   config.TLSRuleConfig{Mode: "passthrough"},
		}},
	}})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	outcome := engine.EvaluateHTTPOutcome(EvaluateInput{
		Identity:              identity.Unknown(),
		SourceIP:              testSourceIP,
		FQDN:                  "example.com",
		Port:                  80,
		Method:                http.MethodGet,
		Path:                  "/",
		EnforcementMode:       config.EnforcementAudit,
		UnknownIdentityPolicy: config.UnknownIdentityDeny,
	})

	if outcome.Action != "allow" {
		t.Fatalf("outcome.Action = %q, want %q", outcome.Action, "allow")
	}
	if outcome.Reason != "audit_unknown_identity" {
		t.Fatalf("outcome.Reason = %q, want %q", outcome.Reason, "audit_unknown_identity")
	}
	if !outcome.Audit.Enabled {
		t.Fatal("outcome.Audit.Enabled = false, want true")
	}
	if outcome.Audit.WouldAction != "would_deny" {
		t.Fatalf("outcome.Audit.WouldAction = %q, want %q", outcome.Audit.WouldAction, "would_deny")
	}
	if outcome.Audit.WouldReason != "unknown_identity" {
		t.Fatalf("outcome.Audit.WouldReason = %q, want %q", outcome.Audit.WouldReason, "unknown_identity")
	}
	if !outcome.Audit.WouldBlock {
		t.Fatal("outcome.Audit.WouldBlock = false, want true")
	}
}

func TestEvaluateHTTPOutcomeNormalizesBypassDeniedRuleAsAuditDeny(t *testing.T) {
	engine, err := NewEngine([]config.PolicyConfig{{
		Name:     "allow-web",
		Bypass:   true,
		Subjects: kubernetesSubjects([]string{"cluster-a"}, []string{"default"}, map[string]string{"app": "web"}),
		Egress: []config.EgressRuleConfig{{
			FQDN:  "example.com",
			Ports: []int{80},
			TLS:   config.TLSRuleConfig{Mode: "passthrough"},
			HTTP: &config.HTTPRuleConfig{
				AllowedMethods: []string{http.MethodGet},
				AllowedPaths:   []string{"/allowed"},
			},
		}},
	}})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	outcome := engine.EvaluateHTTPOutcome(EvaluateInput{
		Identity: kubernetesIdentity("cluster-a", "default", map[string]string{"app": "web"}),
		SourceIP: testSourceIP,
		FQDN:     "example.com",
		Port:     80,
		Method:   http.MethodGet,
		Path:     "/denied",
	})

	if outcome.Action != "allow" {
		t.Fatalf("outcome.Action = %q, want %q", outcome.Action, "allow")
	}
	if outcome.Reason != "audit_policy_denied" {
		t.Fatalf("outcome.Reason = %q, want %q", outcome.Reason, "audit_policy_denied")
	}
	if !outcome.Audit.Enabled {
		t.Fatal("outcome.Audit.Enabled = false, want true")
	}
	if outcome.Audit.WouldAction != "would_deny" {
		t.Fatalf("outcome.Audit.WouldAction = %q, want %q", outcome.Audit.WouldAction, "would_deny")
	}
	if outcome.Audit.WouldReason != "policy_denied" {
		t.Fatalf("outcome.Audit.WouldReason = %q, want %q", outcome.Audit.WouldReason, "policy_denied")
	}
	if !outcome.Audit.PolicyBypass {
		t.Fatal("outcome.Audit.PolicyBypass = false, want true")
	}
}

func TestEvaluateConnectOutcomeReturnsRequestedAndEffectiveTLSModes(t *testing.T) {
	engine, err := NewEngine([]config.PolicyConfig{{
		Name:     "allow-web",
		Subjects: kubernetesSubjects([]string{"cluster-a"}, []string{"default"}, map[string]string{"app": "web"}),
		Egress: []config.EgressRuleConfig{{
			FQDN:  "example.com",
			Ports: []int{443},
			TLS:   config.TLSRuleConfig{Mode: "mitm"},
		}},
	}})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	outcome := engine.EvaluateConnectOutcome(EvaluateInput{
		Identity: kubernetesIdentity("cluster-a", "default", map[string]string{"app": "web"}),
		SourceIP: testSourceIP,
		FQDN:     "example.com",
		Port:     443,
	})

	if outcome.Action != "allow" {
		t.Fatalf("outcome.Action = %q, want %q", outcome.Action, "allow")
	}
	if outcome.Reason != "policy_allowed" {
		t.Fatalf("outcome.Reason = %q, want %q", outcome.Reason, "policy_allowed")
	}
	if outcome.RequestedTLSMode != "mitm" {
		t.Fatalf("outcome.RequestedTLSMode = %q, want %q", outcome.RequestedTLSMode, "mitm")
	}
	if outcome.EffectiveTLSMode != "mitm" {
		t.Fatalf("outcome.EffectiveTLSMode = %q, want %q", outcome.EffectiveTLSMode, "mitm")
	}
}

func TestEvaluateConnectOutcomeFallsBackToPassthroughInAuditMode(t *testing.T) {
	engine, err := NewEngine([]config.PolicyConfig{{
		Name:        "allow-web",
		Enforcement: config.EnforcementAudit,
		Subjects:    kubernetesSubjects([]string{"cluster-a"}, []string{"default"}, map[string]string{"app": "web"}),
		Egress: []config.EgressRuleConfig{{
			FQDN:  "example.com",
			Ports: []int{443},
			TLS:   config.TLSRuleConfig{Mode: "mitm"},
		}},
	}})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	outcome := engine.EvaluateConnectOutcome(EvaluateInput{
		Identity: kubernetesIdentity("cluster-a", "default", map[string]string{"app": "web"}),
		SourceIP: testSourceIP,
		FQDN:     "example.com",
		Port:     443,
	})

	if outcome.Action != "allow" {
		t.Fatalf("outcome.Action = %q, want %q", outcome.Action, "allow")
	}
	if outcome.Reason != "audit_policy_allowed" {
		t.Fatalf("outcome.Reason = %q, want %q", outcome.Reason, "audit_policy_allowed")
	}
	if !outcome.Audit.Enabled {
		t.Fatal("outcome.Audit.Enabled = false, want true")
	}
	if outcome.Audit.WouldAction != "would_allow" {
		t.Fatalf("outcome.Audit.WouldAction = %q, want %q", outcome.Audit.WouldAction, "would_allow")
	}
	if outcome.Audit.WouldReason != "policy_allowed" {
		t.Fatalf("outcome.Audit.WouldReason = %q, want %q", outcome.Audit.WouldReason, "policy_allowed")
	}
	if outcome.RequestedTLSMode != "mitm" {
		t.Fatalf("outcome.RequestedTLSMode = %q, want %q", outcome.RequestedTLSMode, "mitm")
	}
	if outcome.EffectiveTLSMode != "passthrough" {
		t.Fatalf("outcome.EffectiveTLSMode = %q, want %q", outcome.EffectiveTLSMode, "passthrough")
	}
}

func TestEvaluateHTTPOutcomeHandlesUnknownIdentityWithoutPolicyEngine(t *testing.T) {
	outcome := EvaluateHTTPOutcome(nil, EvaluateInput{
		Identity:              identity.Unknown(),
		SourceIP:              testSourceIP,
		FQDN:                  "example.com",
		Port:                  80,
		Method:                http.MethodGet,
		Path:                  "/",
		EnforcementMode:       config.EnforcementAudit,
		UnknownIdentityPolicy: config.UnknownIdentityDeny,
	})

	if outcome.Action != "allow" {
		t.Fatalf("outcome.Action = %q, want %q", outcome.Action, "allow")
	}
	if outcome.Reason != "audit_unknown_identity" {
		t.Fatalf("outcome.Reason = %q, want %q", outcome.Reason, "audit_unknown_identity")
	}
	if !outcome.Audit.Enabled || !outcome.Audit.WouldBlock {
		t.Fatalf("outcome.Audit = %#v, want enabled would-block audit", outcome.Audit)
	}
}

func TestEvaluateHTTPOutcomeAllowsRequestsWithoutPolicyEngineByDefault(t *testing.T) {
	outcome := EvaluateHTTPOutcome(nil, EvaluateInput{
		Identity:        identity.Unknown(),
		SourceIP:        testSourceIP,
		FQDN:            "example.com",
		Port:            80,
		Method:          http.MethodGet,
		Path:            "/",
		EnforcementMode: config.EnforcementEnforce,
	})

	if outcome.Action != "allow" {
		t.Fatalf("outcome.Action = %q, want %q", outcome.Action, "allow")
	}
	if outcome.Reason != "policy_allowed" {
		t.Fatalf("outcome.Reason = %q, want %q", outcome.Reason, "policy_allowed")
	}
}

func TestEvaluateHTTPOutcomeTreatsPolicyAuditEnforcementAsShadow(t *testing.T) {
	engine, err := NewEngine([]config.PolicyConfig{{
		Name:        "allow-web",
		Enforcement: config.EnforcementAudit,
		Subjects:    kubernetesSubjects([]string{"cluster-a"}, []string{"default"}, map[string]string{"app": "web"}),
		Egress: []config.EgressRuleConfig{{
			FQDN:  "example.com",
			Ports: []int{80},
			TLS:   config.TLSRuleConfig{Mode: "passthrough"},
			HTTP: &config.HTTPRuleConfig{
				AllowedMethods: []string{http.MethodGet},
				AllowedPaths:   []string{"/allowed"},
			},
		}},
	}})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	outcome := engine.EvaluateHTTPOutcome(EvaluateInput{
		Identity: kubernetesIdentity("cluster-a", "default", map[string]string{"app": "web"}),
		SourceIP: testSourceIP,
		FQDN:     "example.com",
		Port:     80,
		Method:   http.MethodGet,
		Path:     "/denied",
	})

	if outcome.Action != "allow" {
		t.Fatalf("outcome.Action = %q, want %q", outcome.Action, "allow")
	}
	if outcome.Reason != "audit_policy_denied" {
		t.Fatalf("outcome.Reason = %q, want %q", outcome.Reason, "audit_policy_denied")
	}
	if !outcome.Audit.Enabled || !outcome.Audit.WouldBlock {
		t.Fatalf("outcome.Audit = %#v, want enabled would-block audit", outcome.Audit)
	}
}
