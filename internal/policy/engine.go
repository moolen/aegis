package policy

import (
	"fmt"
	"strings"

	"github.com/moolen/aegis/internal/config"
	"github.com/moolen/aegis/internal/identity"
)

type Engine struct {
	policies []Policy
}

type Decision struct {
	Allowed bool
	Policy  string
	Rule    string
	TLSMode string
}

type Policy struct {
	name     string
	selector map[string]string
	egress   []Rule
}

type Rule struct {
	fqdnPattern string
	ports       map[int]struct{}
	tlsMode     string
	http        *HTTPRule
}

type HTTPRule struct {
	allowedMethods map[string]struct{}
	allowedPaths   []string
}

func NewEngine(cfgs []config.PolicyConfig) (*Engine, error) {
	policies := make([]Policy, 0, len(cfgs))
	for _, cfg := range cfgs {
		policy, err := compilePolicy(cfg)
		if err != nil {
			return nil, err
		}
		policies = append(policies, policy)
	}

	return &Engine{policies: policies}, nil
}

func (e *Engine) Evaluate(id *identity.Identity, fqdn string, port int, method string, reqPath string) *Decision {
	for _, policy := range e.policies {
		if !policy.matchesIdentity(id) {
			continue
		}

		decision := &Decision{Policy: policy.name}
		for _, rule := range policy.egress {
			if !rule.matches(fqdn, port, method, reqPath) {
				continue
			}

			decision.Allowed = true
			decision.Rule = rule.fqdnPattern
			decision.TLSMode = rule.tlsMode
			return decision
		}

		return decision
	}

	return &Decision{}
}

func compilePolicy(cfg config.PolicyConfig) (Policy, error) {
	policy := Policy{
		name:     cfg.Name,
		selector: cloneStringMap(cfg.IdentitySelector.MatchLabels),
		egress:   make([]Rule, 0, len(cfg.Egress)),
	}

	for _, ruleCfg := range cfg.Egress {
		rule, err := compileRule(ruleCfg)
		if err != nil {
			return Policy{}, err
		}
		policy.egress = append(policy.egress, rule)
	}

	return policy, nil
}

func compileRule(cfg config.EgressRuleConfig) (Rule, error) {
	normalizedFQDN := strings.ToLower(cfg.FQDN)
	if err := validateFQDNPattern(normalizedFQDN); err != nil {
		return Rule{}, err
	}

	rule := Rule{
		fqdnPattern: normalizedFQDN,
		ports:       make(map[int]struct{}, len(cfg.Ports)),
		tlsMode:     cfg.TLS.Mode,
	}
	for _, port := range cfg.Ports {
		rule.ports[port] = struct{}{}
	}

	if cfg.HTTP != nil {
		httpRule, err := compileHTTPRule(*cfg.HTTP)
		if err != nil {
			return Rule{}, err
		}
		rule.http = httpRule
	}

	return rule, nil
}

func compileHTTPRule(cfg config.HTTPRuleConfig) (*HTTPRule, error) {
	httpRule := &HTTPRule{
		allowedMethods: make(map[string]struct{}, len(cfg.AllowedMethods)),
		allowedPaths:   make([]string, 0, len(cfg.AllowedPaths)),
	}

	for _, method := range cfg.AllowedMethods {
		httpRule.allowedMethods[strings.ToUpper(method)] = struct{}{}
	}

	for _, pattern := range cfg.AllowedPaths {
		if err := validatePathPattern(pattern); err != nil {
			return nil, err
		}
		httpRule.allowedPaths = append(httpRule.allowedPaths, pattern)
	}

	return httpRule, nil
}

func (p Policy) matchesIdentity(id *identity.Identity) bool {
	labels := map[string]string(nil)
	if id != nil {
		labels = id.Labels
	}

	for key, want := range p.selector {
		if got, ok := labels[key]; !ok || got != want {
			return false
		}
	}

	return true
}

func (r Rule) matches(fqdn string, port int, method string, reqPath string) bool {
	if _, ok := r.ports[port]; !ok {
		return false
	}

	if !matchGlob(r.fqdnPattern, strings.ToLower(fqdn)) {
		return false
	}

	if r.http == nil {
		return true
	}

	return r.http.matches(method, reqPath)
}

func (r HTTPRule) matches(method string, reqPath string) bool {
	if len(r.allowedMethods) > 0 {
		if _, ok := r.allowedMethods[strings.ToUpper(method)]; !ok {
			return false
		}
	}

	if len(r.allowedPaths) > 0 {
		for _, pattern := range r.allowedPaths {
			if matchGlob(pattern, reqPath) {
				return true
			}
		}

		return false
	}

	return true
}

func validatePathPattern(pattern string) error {
	return validateStarOnlyGlob("path", pattern)
}

func validateFQDNPattern(pattern string) error {
	return validateStarOnlyGlob("fqdn", pattern)
}

func validateStarOnlyGlob(kind string, pattern string) error {
	if strings.ContainsAny(pattern, "[]?\\") {
		return fmt.Errorf("unsupported %s glob %q: only '*' wildcards are allowed", kind, pattern)
	}

	return nil
}

// matchGlob implements the supported HTTP path glob contract: literal characters
// plus '*' wildcards only. Unlike path.Match, '*' spans nested path segments.
func matchGlob(pattern string, value string) bool {
	patternIndex := 0
	valueIndex := 0
	starIndex := -1
	matchIndex := 0

	for valueIndex < len(value) {
		switch {
		case patternIndex < len(pattern) && pattern[patternIndex] == value[valueIndex]:
			patternIndex++
			valueIndex++
		case patternIndex < len(pattern) && pattern[patternIndex] == '*':
			starIndex = patternIndex
			matchIndex = valueIndex
			patternIndex++
		case starIndex != -1:
			patternIndex = starIndex + 1
			matchIndex++
			valueIndex = matchIndex
		default:
			return false
		}
	}

	for patternIndex < len(pattern) && pattern[patternIndex] == '*' {
		patternIndex++
	}

	return patternIndex == len(pattern)
}

func cloneStringMap(src map[string]string) map[string]string {
	if len(src) == 0 {
		return nil
	}

	dst := make(map[string]string, len(src))
	for key, value := range src {
		dst[key] = value
	}

	return dst
}
