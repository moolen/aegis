package policy

import (
	"fmt"

	"github.com/moolen/aegis/internal/config"
)

type Warning struct {
	Policy  string
	Message string
}

func Analyze(cfgs []config.PolicyConfig) []Warning {
	warnings := make([]Warning, 0)
	for i := 1; i < len(cfgs); i++ {
		for j := 0; j < i; j++ {
			if selectorCovers(cfgs[j].IdentitySelector.MatchLabels, cfgs[i].IdentitySelector.MatchLabels) {
				warnings = append(warnings, Warning{
					Policy:  cfgs[i].Name,
					Message: fmt.Sprintf("policy %q is shadowed by earlier policy %q because first-match selector precedence makes it unreachable", cfgs[i].Name, cfgs[j].Name),
				})
				break
			}
		}
	}
	return warnings
}

func selectorCovers(earlier map[string]string, later map[string]string) bool {
	for key, value := range earlier {
		if later[key] != value {
			return false
		}
	}
	return true
}
