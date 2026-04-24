package policy

import (
	"net/http"
	"testing"

	"github.com/moolen/aegis/internal/config"
	"github.com/moolen/aegis/internal/identity"
)

func TestEvaluateAllowsMatchingRule(t *testing.T) {
	engine, err := NewEngine([]config.PolicyConfig{{
		Name: "allow-web",
		IdentitySelector: config.IdentitySelectorConfig{
			MatchLabels: map[string]string{"app": "web"},
		},
		Egress: []config.EgressRuleConfig{{
			FQDN:  "example.com",
			Ports: []int{80},
			TLS:   config.TLSRuleConfig{Mode: "mitm"},
			HTTP: &config.HTTPRuleConfig{
				AllowedMethods: []string{"GET"},
				AllowedPaths:   []string{"/api/*"},
			},
		}},
	}})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	decision := engine.Evaluate(
		&identity.Identity{Labels: map[string]string{"app": "web"}},
		"example.com",
		80,
		http.MethodGet,
		"/api/users",
	)
	if !decision.Allowed {
		t.Fatalf("decision.Allowed = false, want true")
	}
	if decision.Policy != "allow-web" {
		t.Fatalf("decision.Policy = %q, want %q", decision.Policy, "allow-web")
	}
	if decision.Rule != "example.com" {
		t.Fatalf("decision.Rule = %q, want %q", decision.Rule, "example.com")
	}
	if decision.TLSMode != "mitm" {
		t.Fatalf("decision.TLSMode = %q, want %q", decision.TLSMode, "mitm")
	}
}

func TestEvaluateAllowsNestedPathMatch(t *testing.T) {
	engine, err := NewEngine([]config.PolicyConfig{{
		Name: "allow-web",
		IdentitySelector: config.IdentitySelectorConfig{
			MatchLabels: map[string]string{"app": "web"},
		},
		Egress: []config.EgressRuleConfig{{
			FQDN:  "example.com",
			Ports: []int{80},
			TLS:   config.TLSRuleConfig{Mode: "mitm"},
			HTTP: &config.HTTPRuleConfig{
				AllowedPaths: []string{"/api/*"},
			},
		}},
	}})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	decision := engine.Evaluate(
		&identity.Identity{Labels: map[string]string{"app": "web"}},
		"example.com",
		80,
		http.MethodGet,
		"/api/v1/users",
	)
	if !decision.Allowed {
		t.Fatalf("decision.Allowed = false, want true")
	}
}

func TestEvaluateDeniesWhenNoPolicyMatches(t *testing.T) {
	engine, err := NewEngine([]config.PolicyConfig{{
		Name: "allow-web",
		IdentitySelector: config.IdentitySelectorConfig{
			MatchLabels: map[string]string{"app": "web"},
		},
		Egress: []config.EgressRuleConfig{{
			FQDN:  "example.com",
			Ports: []int{80},
			TLS:   config.TLSRuleConfig{Mode: "mitm"},
		}},
	}})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	decision := engine.Evaluate(
		&identity.Identity{Labels: map[string]string{"app": "api"}},
		"example.com",
		80,
		http.MethodGet,
		"/",
	)
	if decision.Allowed {
		t.Fatalf("decision.Allowed = true, want false")
	}
	if decision.Policy != "" {
		t.Fatalf("decision.Policy = %q, want empty", decision.Policy)
	}
	if decision.Rule != "" {
		t.Fatalf("decision.Rule = %q, want empty", decision.Rule)
	}
	if decision.TLSMode != "" {
		t.Fatalf("decision.TLSMode = %q, want empty", decision.TLSMode)
	}
}

func TestEvaluateDeniesUnknownIdentity(t *testing.T) {
	engine, err := NewEngine([]config.PolicyConfig{{
		Name: "allow-web",
		IdentitySelector: config.IdentitySelectorConfig{
			MatchLabels: map[string]string{"app": "web"},
		},
		Egress: []config.EgressRuleConfig{{
			FQDN:  "example.com",
			Ports: []int{80},
			TLS:   config.TLSRuleConfig{Mode: "mitm"},
		}},
	}})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	decision := engine.Evaluate(nil, "example.com", 80, http.MethodGet, "/")
	if decision.Allowed {
		t.Fatalf("decision.Allowed = true, want false")
	}
}

func TestEvaluateFirstMatchWins(t *testing.T) {
	engine, err := NewEngine([]config.PolicyConfig{
		{
			Name: "deny-first",
			IdentitySelector: config.IdentitySelectorConfig{
				MatchLabels: map[string]string{"app": "web"},
			},
			Egress: []config.EgressRuleConfig{{
				FQDN:  "internal.example.com",
				Ports: []int{443},
				TLS:   config.TLSRuleConfig{Mode: "mitm"},
			}},
		},
		{
			Name: "allow-second",
			IdentitySelector: config.IdentitySelectorConfig{
				MatchLabels: map[string]string{"app": "web"},
			},
			Egress: []config.EgressRuleConfig{{
				FQDN:  "example.com",
				Ports: []int{80},
				TLS:   config.TLSRuleConfig{Mode: "mitm"},
			}},
		},
	})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	decision := engine.Evaluate(
		&identity.Identity{Labels: map[string]string{"app": "web"}},
		"example.com",
		80,
		http.MethodGet,
		"/",
	)
	if decision.Allowed {
		t.Fatalf("decision.Allowed = true, want false")
	}
	if decision.Policy != "deny-first" {
		t.Fatalf("decision.Policy = %q, want %q", decision.Policy, "deny-first")
	}
}

func TestEvaluateDeniesPortMismatch(t *testing.T) {
	engine, err := NewEngine([]config.PolicyConfig{{
		Name: "allow-web",
		IdentitySelector: config.IdentitySelectorConfig{
			MatchLabels: map[string]string{"app": "web"},
		},
		Egress: []config.EgressRuleConfig{{
			FQDN:  "example.com",
			Ports: []int{443},
			TLS:   config.TLSRuleConfig{Mode: "mitm"},
		}},
	}})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	decision := engine.Evaluate(
		&identity.Identity{Labels: map[string]string{"app": "web"}},
		"example.com",
		80,
		http.MethodGet,
		"/",
	)
	if decision.Allowed {
		t.Fatalf("decision.Allowed = true, want false")
	}
	if decision.Policy != "allow-web" {
		t.Fatalf("decision.Policy = %q, want %q", decision.Policy, "allow-web")
	}
}

func TestEvaluateDeniesMethodMismatch(t *testing.T) {
	engine, err := NewEngine([]config.PolicyConfig{{
		Name: "allow-web",
		IdentitySelector: config.IdentitySelectorConfig{
			MatchLabels: map[string]string{"app": "web"},
		},
		Egress: []config.EgressRuleConfig{{
			FQDN:  "example.com",
			Ports: []int{80},
			TLS:   config.TLSRuleConfig{Mode: "mitm"},
			HTTP: &config.HTTPRuleConfig{
				AllowedMethods: []string{"GET"},
			},
		}},
	}})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	decision := engine.Evaluate(
		&identity.Identity{Labels: map[string]string{"app": "web"}},
		"example.com",
		80,
		http.MethodPost,
		"/",
	)
	if decision.Allowed {
		t.Fatalf("decision.Allowed = true, want false")
	}
	if decision.Policy != "allow-web" {
		t.Fatalf("decision.Policy = %q, want %q", decision.Policy, "allow-web")
	}
}

func TestEvaluateDeniesPathMismatch(t *testing.T) {
	engine, err := NewEngine([]config.PolicyConfig{{
		Name: "allow-web",
		IdentitySelector: config.IdentitySelectorConfig{
			MatchLabels: map[string]string{"app": "web"},
		},
		Egress: []config.EgressRuleConfig{{
			FQDN:  "example.com",
			Ports: []int{80},
			TLS:   config.TLSRuleConfig{Mode: "mitm"},
			HTTP: &config.HTTPRuleConfig{
				AllowedPaths: []string{"/api/*"},
			},
		}},
	}})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	decision := engine.Evaluate(
		&identity.Identity{Labels: map[string]string{"app": "web"}},
		"example.com",
		80,
		http.MethodGet,
		"/admin",
	)
	if decision.Allowed {
		t.Fatalf("decision.Allowed = true, want false")
	}
	if decision.Policy != "allow-web" {
		t.Fatalf("decision.Policy = %q, want %q", decision.Policy, "allow-web")
	}
}

func TestEvaluateMatchesFQDNGlob(t *testing.T) {
	engine, err := NewEngine([]config.PolicyConfig{{
		Name: "allow-web",
		IdentitySelector: config.IdentitySelectorConfig{
			MatchLabels: map[string]string{"app": "web"},
		},
		Egress: []config.EgressRuleConfig{{
			FQDN:  "*.example.com",
			Ports: []int{443},
			TLS:   config.TLSRuleConfig{Mode: "passthrough"},
		}},
	}})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	decision := engine.Evaluate(
		&identity.Identity{Labels: map[string]string{"app": "web"}},
		"api.example.com",
		443,
		http.MethodGet,
		"/",
	)
	if !decision.Allowed {
		t.Fatalf("decision.Allowed = false, want true")
	}
	if decision.Rule != "*.example.com" {
		t.Fatalf("decision.Rule = %q, want %q", decision.Rule, "*.example.com")
	}
	if decision.TLSMode != "passthrough" {
		t.Fatalf("decision.TLSMode = %q, want %q", decision.TLSMode, "passthrough")
	}
}

func TestEvaluateMatchesFQDNCaseInsensitively(t *testing.T) {
	engine, err := NewEngine([]config.PolicyConfig{{
		Name: "allow-web",
		IdentitySelector: config.IdentitySelectorConfig{
			MatchLabels: map[string]string{"app": "web"},
		},
		Egress: []config.EgressRuleConfig{{
			FQDN:  "*.example.com",
			Ports: []int{443},
			TLS:   config.TLSRuleConfig{Mode: "passthrough"},
		}},
	}})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	decision := engine.Evaluate(
		&identity.Identity{Labels: map[string]string{"app": "web"}},
		"API.EXAMPLE.COM",
		443,
		http.MethodGet,
		"/",
	)
	if !decision.Allowed {
		t.Fatalf("decision.Allowed = false, want true")
	}
}
