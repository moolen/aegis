package policy

import (
	"net/http"
	"strings"
	"testing"

	"github.com/moolen/aegis/internal/config"
	"github.com/moolen/aegis/internal/identity"
)

const testKubernetesNamespaceLabel = "kubernetes.io/namespace"

func kubernetesSubjects(discoveryNames []string, namespaces []string, matchLabels map[string]string) config.PolicySubjectsConfig {
	return config.PolicySubjectsConfig{
		Kubernetes: &config.KubernetesSubjectConfig{
			DiscoveryNames: append([]string(nil), discoveryNames...),
			Namespaces:     append([]string(nil), namespaces...),
			MatchLabels:    cloneStringMap(matchLabels),
		},
	}
}

func ec2Subjects(discoveryNames []string) config.PolicySubjectsConfig {
	return config.PolicySubjectsConfig{
		EC2: &config.EC2SubjectConfig{
			DiscoveryNames: append([]string(nil), discoveryNames...),
		},
	}
}

func kubernetesIdentity(provider string, namespace string, labels map[string]string) *identity.Identity {
	identityLabels := map[string]string{
		testKubernetesNamespaceLabel: namespace,
	}
	for key, value := range labels {
		identityLabels[key] = value
	}

	return &identity.Identity{
		Source:   "kubernetes",
		Provider: provider,
		Labels:   identityLabels,
	}
}

func ec2Identity(provider string) *identity.Identity {
	return &identity.Identity{
		Source:   "ec2",
		Provider: provider,
		Labels:   map[string]string{},
	}
}

func TestNewEngineRejectsMalformedPathPattern(t *testing.T) {
	_, err := NewEngine([]config.PolicyConfig{{
		Name:     "allow-web",
		Subjects: kubernetesSubjects([]string{"cluster-a"}, []string{"default"}, map[string]string{"app": "web"}),
		Egress: []config.EgressRuleConfig{{
			FQDN:  "example.com",
			Ports: []int{80},
			TLS:   config.TLSRuleConfig{Mode: "mitm"},
			HTTP: &config.HTTPRuleConfig{
				AllowedPaths: []string{"/api/["},
			},
		}},
	}})
	if err == nil {
		t.Fatal("NewEngine() error = nil, want invalid path pattern error")
	}
	if !strings.Contains(err.Error(), "unsupported path glob") {
		t.Fatalf("NewEngine() error = %q, want unsupported path glob", err)
	}
}

func TestNewEngineRejectsUnsupportedPathMetacharacters(t *testing.T) {
	_, err := NewEngine([]config.PolicyConfig{{
		Name:     "allow-web",
		Subjects: kubernetesSubjects([]string{"cluster-a"}, []string{"default"}, map[string]string{"app": "web"}),
		Egress: []config.EgressRuleConfig{{
			FQDN:  "example.com",
			Ports: []int{80},
			TLS:   config.TLSRuleConfig{Mode: "mitm"},
			HTTP: &config.HTTPRuleConfig{
				AllowedPaths: []string{"/api/?"},
			},
		}},
	}})
	if err == nil {
		t.Fatal("NewEngine() error = nil, want invalid path pattern error")
	}
	if !strings.Contains(err.Error(), "only '*'") {
		t.Fatalf("NewEngine() error = %q, want '*' only contract", err)
	}
}

func TestNewEngineRejectsUnsupportedFQDNMetacharacters(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
	}{
		{name: "question mark", pattern: "api?.example.com"},
		{name: "character class", pattern: "api[0-9].example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewEngine([]config.PolicyConfig{{
				Name:     "allow-web",
				Subjects: kubernetesSubjects([]string{"cluster-a"}, []string{"default"}, map[string]string{"app": "web"}),
				Egress: []config.EgressRuleConfig{{
					FQDN:  tt.pattern,
					Ports: []int{80},
					TLS:   config.TLSRuleConfig{Mode: "mitm"},
				}},
			}})
			if err == nil {
				t.Fatal("NewEngine() error = nil, want invalid fqdn pattern error")
			}
			if !strings.Contains(err.Error(), "unsupported fqdn glob") {
				t.Fatalf("NewEngine() error = %q, want unsupported fqdn glob", err)
			}
			if !strings.Contains(err.Error(), "only '*'") {
				t.Fatalf("NewEngine() error = %q, want '*' only contract", err)
			}
		})
	}
}

func TestNewEngineRejectsKubernetesSubjectsWithoutDiscoveryNames(t *testing.T) {
	_, err := NewEngine([]config.PolicyConfig{{
		Name:     "frontend-egress",
		Subjects: kubernetesSubjects(nil, []string{"frontend"}, map[string]string{"app": "frontend"}),
		Egress: []config.EgressRuleConfig{{
			FQDN:  "api.stripe.com",
			Ports: []int{443},
			TLS:   config.TLSRuleConfig{Mode: "passthrough"},
		}},
	}})
	if err == nil {
		t.Fatal("NewEngine() error = nil, want kubernetes discoveryNames validation error")
	}
	if !strings.Contains(err.Error(), "kubernetes") || !strings.Contains(err.Error(), "discoveryNames") {
		t.Fatalf("NewEngine() error = %q, want kubernetes discoveryNames validation error", err)
	}
}

func TestNewEngineRejectsKubernetesSubjectsWithoutNamespaces(t *testing.T) {
	_, err := NewEngine([]config.PolicyConfig{{
		Name:     "frontend-egress",
		Subjects: kubernetesSubjects([]string{"cluster-a"}, nil, map[string]string{"app": "frontend"}),
		Egress: []config.EgressRuleConfig{{
			FQDN:  "api.stripe.com",
			Ports: []int{443},
			TLS:   config.TLSRuleConfig{Mode: "passthrough"},
		}},
	}})
	if err == nil {
		t.Fatal("NewEngine() error = nil, want kubernetes namespaces validation error")
	}
	if !strings.Contains(err.Error(), "kubernetes") || !strings.Contains(err.Error(), "namespaces") {
		t.Fatalf("NewEngine() error = %q, want kubernetes namespaces validation error", err)
	}
}

func TestNewEngineRejectsEC2SubjectsWithoutDiscoveryNames(t *testing.T) {
	_, err := NewEngine([]config.PolicyConfig{{
		Name:     "legacy-web-egress",
		Subjects: ec2Subjects(nil),
		Egress: []config.EgressRuleConfig{{
			FQDN:  "metadata.internal",
			Ports: []int{443},
			TLS:   config.TLSRuleConfig{Mode: "passthrough"},
		}},
	}})
	if err == nil {
		t.Fatal("NewEngine() error = nil, want ec2 discoveryNames validation error")
	}
	if !strings.Contains(err.Error(), "ec2") || !strings.Contains(err.Error(), "discoveryNames") {
		t.Fatalf("NewEngine() error = %q, want ec2 discoveryNames validation error", err)
	}
}

func TestNewEngineRejectsPoliciesWithoutAnySubjects(t *testing.T) {
	_, err := NewEngine([]config.PolicyConfig{{
		Name: "orphan-policy",
		Egress: []config.EgressRuleConfig{{
			FQDN:  "example.com",
			Ports: []int{443},
			TLS:   config.TLSRuleConfig{Mode: "passthrough"},
		}},
	}})
	if err == nil {
		t.Fatal("NewEngine() error = nil, want empty subjects validation error")
	}
	if !strings.Contains(err.Error(), "subjects") {
		t.Fatalf("NewEngine() error = %q, want subjects validation error", err)
	}
}

func TestEvaluateMatchesKubernetesSubjectForBoundProviderOnly(t *testing.T) {
	engine, err := NewEngine([]config.PolicyConfig{{
		Name:     "frontend-egress",
		Subjects: kubernetesSubjects([]string{"cluster-a"}, []string{"frontend"}, map[string]string{"app": "frontend"}),
		Egress: []config.EgressRuleConfig{{
			FQDN:  "api.stripe.com",
			Ports: []int{443},
			TLS:   config.TLSRuleConfig{Mode: "passthrough"},
		}},
	}})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	allowed := engine.EvaluateConnect(
		kubernetesIdentity("cluster-a", "frontend", map[string]string{"app": "frontend"}),
		"api.stripe.com",
		443,
	)
	if !allowed.Allowed {
		t.Fatal("expected cluster-a identity to match")
	}

	denied := engine.EvaluateConnect(
		kubernetesIdentity("cluster-b", "frontend", map[string]string{"app": "frontend"}),
		"api.stripe.com",
		443,
	)
	if denied.Allowed {
		t.Fatal("expected cluster-b identity not to match cluster-a-scoped policy")
	}
}

func TestEvaluateMatchesKubernetesSubjectWithEmptyMatchLabels(t *testing.T) {
	engine, err := NewEngine([]config.PolicyConfig{{
		Name:     "frontend-egress",
		Subjects: kubernetesSubjects([]string{"cluster-a"}, []string{"frontend"}, nil),
		Egress: []config.EgressRuleConfig{{
			FQDN:  "api.stripe.com",
			Ports: []int{443},
			TLS:   config.TLSRuleConfig{Mode: "passthrough"},
		}},
	}})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	decision := engine.EvaluateConnect(
		kubernetesIdentity("cluster-a", "frontend", map[string]string{"any": "label"}),
		"api.stripe.com",
		443,
	)
	if !decision.Allowed {
		t.Fatal("expected empty kubernetes matchLabels to behave as a label wildcard")
	}
}

func TestEvaluateMatchesSharedKubernetesSelectorAcrossMultipleProviders(t *testing.T) {
	engine, err := NewEngine([]config.PolicyConfig{{
		Name:     "frontend-egress",
		Subjects: kubernetesSubjects([]string{"cluster-a", "cluster-b"}, []string{"frontend"}, map[string]string{"app": "frontend"}),
		Egress: []config.EgressRuleConfig{{
			FQDN:  "api.stripe.com",
			Ports: []int{443},
			TLS:   config.TLSRuleConfig{Mode: "passthrough"},
		}},
	}})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	for _, provider := range []string{"cluster-a", "cluster-b"} {
		t.Run(provider, func(t *testing.T) {
			decision := engine.EvaluateConnect(
				kubernetesIdentity(provider, "frontend", map[string]string{"app": "frontend"}),
				"api.stripe.com",
				443,
			)
			if !decision.Allowed {
				t.Fatalf("expected provider %q to match shared kubernetes subject", provider)
			}
		})
	}
}

func TestEvaluateMatchesEC2ProviderBindingWithoutLabelSelector(t *testing.T) {
	engine, err := NewEngine([]config.PolicyConfig{{
		Name:     "legacy-web-egress",
		Subjects: ec2Subjects([]string{"legacy-web"}),
		Egress: []config.EgressRuleConfig{{
			FQDN:  "metadata.internal",
			Ports: []int{443},
			TLS:   config.TLSRuleConfig{Mode: "passthrough"},
		}},
	}})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	allowed := engine.EvaluateConnect(ec2Identity("legacy-web"), "metadata.internal", 443)
	if !allowed.Allowed {
		t.Fatal("expected ec2 identity bound to legacy-web provider to match")
	}

	denied := engine.EvaluateConnect(ec2Identity("batch-workers"), "metadata.internal", 443)
	if denied.Allowed {
		t.Fatal("expected ec2 identity bound to batch-workers not to match legacy-web policy")
	}
}

func TestEvaluateSkipsPolicyWhenIdentitySourceHasNoMatchingSubject(t *testing.T) {
	engine, err := NewEngine([]config.PolicyConfig{{
		Name:     "legacy-web-egress",
		Subjects: ec2Subjects([]string{"legacy-web"}),
		Egress: []config.EgressRuleConfig{{
			FQDN:  "metadata.internal",
			Ports: []int{443},
			TLS:   config.TLSRuleConfig{Mode: "passthrough"},
		}},
	}})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	decision := engine.EvaluateConnect(
		kubernetesIdentity("cluster-a", "default", map[string]string{"app": "web"}),
		"metadata.internal",
		443,
	)
	if decision.Allowed {
		t.Fatal("expected kubernetes identity not to match ec2-only policy")
	}
	if decision.Policy != "" {
		t.Fatalf("decision.Policy = %q, want empty", decision.Policy)
	}
}

func TestEvaluateDoesNotMatchKubernetesSubjectWithoutNamespaceLabel(t *testing.T) {
	engine, err := NewEngine([]config.PolicyConfig{{
		Name:     "frontend-egress",
		Subjects: kubernetesSubjects([]string{"cluster-a"}, []string{"frontend"}, map[string]string{"app": "frontend"}),
		Egress: []config.EgressRuleConfig{{
			FQDN:  "api.stripe.com",
			Ports: []int{443},
			TLS:   config.TLSRuleConfig{Mode: "passthrough"},
		}},
	}})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	decision := engine.EvaluateConnect(&identity.Identity{
		Source:   "kubernetes",
		Provider: "cluster-a",
		Labels:   map[string]string{"app": "frontend"},
	}, "api.stripe.com", 443)
	if decision.Allowed {
		t.Fatal("expected kubernetes identity without namespace label not to match")
	}
}

func TestEvaluateDoesNotMatchKubernetesSubjectWithNilLabels(t *testing.T) {
	engine, err := NewEngine([]config.PolicyConfig{{
		Name:     "frontend-egress",
		Subjects: kubernetesSubjects([]string{"cluster-a"}, []string{"frontend"}, map[string]string{"app": "frontend"}),
		Egress: []config.EgressRuleConfig{{
			FQDN:  "api.stripe.com",
			Ports: []int{443},
			TLS:   config.TLSRuleConfig{Mode: "passthrough"},
		}},
	}})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	decision := engine.EvaluateConnect(&identity.Identity{
		Source:   "kubernetes",
		Provider: "cluster-a",
		Labels:   nil,
	}, "api.stripe.com", 443)
	if decision.Allowed {
		t.Fatal("expected kubernetes identity with nil labels not to match")
	}
}

func TestEvaluateAllowsMatchingRule(t *testing.T) {
	engine, err := NewEngine([]config.PolicyConfig{{
		Name:     "allow-web",
		Subjects: kubernetesSubjects([]string{"cluster-a"}, []string{"default"}, map[string]string{"app": "web"}),
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
		kubernetesIdentity("cluster-a", "default", map[string]string{"app": "web"}),
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

func TestEvaluateCarriesBypassPolicyState(t *testing.T) {
	engine, err := NewEngine([]config.PolicyConfig{{
		Name:     "break-glass",
		Bypass:   true,
		Subjects: kubernetesSubjects([]string{"cluster-a"}, []string{"default"}, map[string]string{"app": "web"}),
		Egress: []config.EgressRuleConfig{{
			FQDN:  "example.com",
			Ports: []int{80},
			TLS:   config.TLSRuleConfig{Mode: "mitm"},
			HTTP: &config.HTTPRuleConfig{
				AllowedMethods: []string{"POST"},
				AllowedPaths:   []string{"/*"},
			},
		}},
	}})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	decision := engine.Evaluate(
		kubernetesIdentity("cluster-a", "default", map[string]string{"app": "web"}),
		"example.com",
		80,
		http.MethodGet,
		"/blocked",
	)
	if decision.Allowed {
		t.Fatalf("decision.Allowed = true, want false")
	}
	if !decision.Bypass {
		t.Fatal("decision.Bypass = false, want true")
	}
	if decision.Policy != "break-glass" {
		t.Fatalf("decision.Policy = %q, want %q", decision.Policy, "break-glass")
	}
}

func TestEvaluateCarriesPolicyLevelEnforcementState(t *testing.T) {
	engine, err := NewEngine([]config.PolicyConfig{{
		Name:        "legacy-reporting",
		Enforcement: "audit",
		Subjects:    kubernetesSubjects([]string{"cluster-a"}, []string{"default"}, map[string]string{"app": "reporting"}),
		Egress: []config.EgressRuleConfig{{
			FQDN:  "reports.example.com",
			Ports: []int{443},
			TLS:   config.TLSRuleConfig{Mode: "passthrough"},
		}},
	}})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	decision := engine.EvaluateConnect(
		kubernetesIdentity("cluster-a", "default", map[string]string{"app": "reporting"}),
		"denied.example.com",
		443,
	)
	if decision.PolicyEnforcement != "audit" {
		t.Fatalf("decision.PolicyEnforcement = %q, want audit", decision.PolicyEnforcement)
	}
}

func TestEvaluateAllowsNestedPathMatch(t *testing.T) {
	engine, err := NewEngine([]config.PolicyConfig{{
		Name:     "allow-web",
		Subjects: kubernetesSubjects([]string{"cluster-a"}, []string{"default"}, map[string]string{"app": "web"}),
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
		kubernetesIdentity("cluster-a", "default", map[string]string{"app": "web"}),
		"example.com",
		80,
		http.MethodGet,
		"/api/v1/users",
	)
	if !decision.Allowed {
		t.Fatalf("decision.Allowed = false, want true")
	}
}

func TestEvaluateAllowsFQDNStarMatchCaseInsensitive(t *testing.T) {
	engine, err := NewEngine([]config.PolicyConfig{{
		Name:     "allow-web",
		Subjects: kubernetesSubjects([]string{"cluster-a"}, []string{"default"}, map[string]string{"app": "web"}),
		Egress: []config.EgressRuleConfig{{
			FQDN:  "*.example.com",
			Ports: []int{443},
			TLS:   config.TLSRuleConfig{Mode: "mitm"},
		}},
	}})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	decision := engine.Evaluate(
		kubernetesIdentity("cluster-a", "default", map[string]string{"app": "web"}),
		"API.Example.COM",
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
}

func TestEvaluateDeniesWhenNoPolicyMatches(t *testing.T) {
	engine, err := NewEngine([]config.PolicyConfig{{
		Name:     "allow-web",
		Subjects: kubernetesSubjects([]string{"cluster-a"}, []string{"default"}, map[string]string{"app": "web"}),
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
		kubernetesIdentity("cluster-a", "default", map[string]string{"app": "api"}),
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
		Name:     "allow-web",
		Subjects: kubernetesSubjects([]string{"cluster-a"}, []string{"default"}, map[string]string{"app": "web"}),
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
			Name:     "deny-first",
			Subjects: kubernetesSubjects([]string{"cluster-a"}, []string{"default"}, map[string]string{"app": "web"}),
			Egress: []config.EgressRuleConfig{{
				FQDN:  "internal.example.com",
				Ports: []int{443},
				TLS:   config.TLSRuleConfig{Mode: "mitm"},
			}},
		},
		{
			Name:     "allow-second",
			Subjects: kubernetesSubjects([]string{"cluster-a"}, []string{"default"}, map[string]string{"app": "web"}),
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
		kubernetesIdentity("cluster-a", "default", map[string]string{"app": "web"}),
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

func TestEvaluateConnectFirstMatchWins(t *testing.T) {
	engine, err := NewEngine([]config.PolicyConfig{
		{
			Name:     "deny-first",
			Subjects: kubernetesSubjects([]string{"cluster-a"}, []string{"default"}, map[string]string{"app": "web"}),
			Egress: []config.EgressRuleConfig{{
				FQDN:  "internal.example.com",
				Ports: []int{443},
				TLS:   config.TLSRuleConfig{Mode: "mitm"},
			}},
		},
		{
			Name:     "allow-second",
			Subjects: kubernetesSubjects([]string{"cluster-a"}, []string{"default"}, map[string]string{"app": "web"}),
			Egress: []config.EgressRuleConfig{{
				FQDN:  "example.com",
				Ports: []int{443},
				TLS:   config.TLSRuleConfig{Mode: "passthrough"},
			}},
		},
	})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	decision := engine.EvaluateConnect(
		kubernetesIdentity("cluster-a", "default", map[string]string{"app": "web"}),
		"example.com",
		443,
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

	decision := engine.Evaluate(
		kubernetesIdentity("cluster-a", "default", map[string]string{"app": "web"}),
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
		Name:     "allow-web",
		Subjects: kubernetesSubjects([]string{"cluster-a"}, []string{"default"}, map[string]string{"app": "web"}),
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
		kubernetesIdentity("cluster-a", "default", map[string]string{"app": "web"}),
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
		Name:     "allow-web",
		Subjects: kubernetesSubjects([]string{"cluster-a"}, []string{"default"}, map[string]string{"app": "web"}),
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
		kubernetesIdentity("cluster-a", "default", map[string]string{"app": "web"}),
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
		Name:     "allow-web",
		Subjects: kubernetesSubjects([]string{"cluster-a"}, []string{"default"}, map[string]string{"app": "web"}),
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
		kubernetesIdentity("cluster-a", "default", map[string]string{"app": "web"}),
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
		Name:     "allow-web",
		Subjects: kubernetesSubjects([]string{"cluster-a"}, []string{"default"}, map[string]string{"app": "web"}),
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
		kubernetesIdentity("cluster-a", "default", map[string]string{"app": "web"}),
		"API.EXAMPLE.COM",
		443,
		http.MethodGet,
		"/",
	)
	if !decision.Allowed {
		t.Fatalf("decision.Allowed = false, want true")
	}
}

func TestEvaluateConnectMatchesPassthroughRuleWithoutHTTPInspection(t *testing.T) {
	engine, err := NewEngine([]config.PolicyConfig{{
		Name:     "allow-web",
		Subjects: kubernetesSubjects([]string{"cluster-a"}, []string{"default"}, map[string]string{"app": "web"}),
		Egress: []config.EgressRuleConfig{{
			FQDN:  "example.com",
			Ports: []int{443},
			TLS:   config.TLSRuleConfig{Mode: "passthrough"},
		}},
	}})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	decision := engine.EvaluateConnect(
		kubernetesIdentity("cluster-a", "default", map[string]string{"app": "web"}),
		"example.com",
		443,
	)
	if !decision.Allowed {
		t.Fatalf("decision.Allowed = false, want true")
	}
	if decision.TLSMode != "passthrough" {
		t.Fatalf("decision.TLSMode = %q, want %q", decision.TLSMode, "passthrough")
	}
}

func TestEvaluateConnectReturnsMITMDecisionWithoutHTTPMatch(t *testing.T) {
	engine, err := NewEngine([]config.PolicyConfig{{
		Name:     "allow-web",
		Subjects: kubernetesSubjects([]string{"cluster-a"}, []string{"default"}, map[string]string{"app": "web"}),
		Egress: []config.EgressRuleConfig{{
			FQDN:  "example.com",
			Ports: []int{443},
			TLS:   config.TLSRuleConfig{Mode: "mitm"},
			HTTP: &config.HTTPRuleConfig{
				AllowedMethods: []string{"GET"},
				AllowedPaths:   []string{"/allowed"},
			},
		}},
	}})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	decision := engine.EvaluateConnect(
		kubernetesIdentity("cluster-a", "default", map[string]string{"app": "web"}),
		"example.com",
		443,
	)
	if !decision.Allowed {
		t.Fatalf("decision.Allowed = false, want true")
	}
	if decision.TLSMode != "mitm" {
		t.Fatalf("decision.TLSMode = %q, want %q", decision.TLSMode, "mitm")
	}
}
