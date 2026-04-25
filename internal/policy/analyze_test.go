package policy

import (
	"testing"

	"github.com/moolen/aegis/internal/config"
)

func TestAnalyzeWarnsAboutSelectorShadowing(t *testing.T) {
	warnings := Analyze([]config.PolicyConfig{
		{
			Name: "catch-all",
			IdentitySelector: config.IdentitySelectorConfig{
				MatchLabels: map[string]string{},
			},
		},
		{
			Name: "web-only",
			IdentitySelector: config.IdentitySelectorConfig{
				MatchLabels: map[string]string{"app": "web"},
			},
		},
	})

	if len(warnings) != 1 {
		t.Fatalf("warnings = %#v, want one shadow warning", warnings)
	}
	if warnings[0].Policy != "web-only" {
		t.Fatalf("warning policy = %q, want %q", warnings[0].Policy, "web-only")
	}
}
