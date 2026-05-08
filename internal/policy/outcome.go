package policy

import (
	"net/netip"

	"github.com/moolen/aegis/internal/config"
	"github.com/moolen/aegis/internal/identity"
)

type EvaluateInput struct {
	Identity              *identity.Identity
	SourceIP              netip.Addr
	FQDN                  string
	Port                  int
	Method                string
	Path                  string
	EnforcementMode       string
	UnknownIdentityPolicy string
}

type AuditOutcome struct {
	Enabled      bool
	WouldAction  string
	WouldReason  string
	WouldBlock   bool
	PolicyBypass bool
}

type DecisionEvaluator interface {
	Evaluate(id *identity.Identity, sourceIP netip.Addr, fqdn string, port int, method string, path string) *Decision
	EvaluateConnect(id *identity.Identity, sourceIP netip.Addr, fqdn string, port int) *Decision
}

type Outcome struct {
	Allowed           bool
	Matched           bool
	Action            string
	Reason            string
	Policy            string
	Rule              string
	RequestedTLSMode  string
	EffectiveTLSMode  string
	Audit             AuditOutcome
	PolicyBypass      bool
	PolicyEnforcement string
}

func (e *Engine) EvaluateHTTPOutcome(input EvaluateInput) Outcome {
	return EvaluateHTTPOutcome(e, input)
}

func (e *Engine) EvaluateConnectOutcome(input EvaluateInput) Outcome {
	return EvaluateConnectOutcome(e, input)
}

func EvaluateHTTPOutcome(engine DecisionEvaluator, input EvaluateInput) Outcome {
	return evaluateOutcome(engine, "http", input)
}

func EvaluateConnectOutcome(engine DecisionEvaluator, input EvaluateInput) Outcome {
	return evaluateOutcome(engine, "connect", input)
}

func evaluateOutcome(engine DecisionEvaluator, protocol string, input EvaluateInput) Outcome {
	hasPolicyEngine := engine != nil
	decision := collapseEmptyDecision(evaluateDecision(engine, protocol, input))
	outcome := outcomeFromDecision(decision)

	enforcementMode := config.NormalizeEnforcementMode(input.EnforcementMode)
	unknownIdentityPolicy := config.NormalizeUnknownIdentityPolicy(input.UnknownIdentityPolicy)

	if isUnknownIdentity(input.Identity) && unknownIdentityPolicy == config.UnknownIdentityDeny && decision == nil {
		if enforcementMode == config.EnforcementAudit {
			outcome.Action = "allow"
			outcome.Reason = "audit_unknown_identity"
			outcome.Audit = AuditOutcome{
				Enabled:     true,
				WouldAction: "would_deny",
				WouldReason: "unknown_identity",
				WouldBlock:  true,
			}
			if protocol == "connect" {
				outcome.EffectiveTLSMode = "passthrough"
			}
			return outcome
		}

		outcome.Action = "deny"
		outcome.Reason = "unknown_identity"
		return outcome
	}

	if !hasPolicyEngine {
		outcome.Action = "allow"
		outcome.Reason = "policy_allowed"
		if protocol == "connect" {
			outcome.EffectiveTLSMode = "passthrough"
		}
		return outcome
	}

	shadow := enforcementMode == config.EnforcementAudit || (decision != nil && (decision.Bypass || decision.PolicyEnforcement == config.EnforcementAudit))
	if shadow {
		outcome.Action = "allow"
		outcome.Audit = AuditOutcome{
			Enabled:      true,
			PolicyBypass: decision != nil && decision.Bypass,
		}
		if decision == nil || !decision.Allowed {
			outcome.Reason = "audit_policy_denied"
			outcome.Audit.WouldAction = "would_deny"
			outcome.Audit.WouldReason = "policy_denied"
			outcome.Audit.WouldBlock = true
		} else {
			outcome.Reason = "audit_policy_allowed"
			outcome.Audit.WouldAction = "would_allow"
			outcome.Audit.WouldReason = "policy_allowed"
		}
		if protocol == "connect" {
			outcome.EffectiveTLSMode = "passthrough"
		}
		return outcome
	}

	if decision == nil || !decision.Allowed {
		outcome.Action = "deny"
		outcome.Reason = "policy_denied"
		return outcome
	}

	outcome.Action = "allow"
	outcome.Reason = "policy_allowed"
	if protocol == "connect" {
		outcome.EffectiveTLSMode = connectTLSMode(outcome.RequestedTLSMode)
	}
	return outcome
}

func evaluateDecision(engine DecisionEvaluator, protocol string, input EvaluateInput) *Decision {
	if engine == nil {
		return nil
	}
	switch protocol {
	case "http":
		return engine.Evaluate(input.Identity, input.SourceIP, input.FQDN, input.Port, input.Method, input.Path)
	case "connect":
		return engine.EvaluateConnect(input.Identity, input.SourceIP, input.FQDN, input.Port)
	default:
		return nil
	}
}

func outcomeFromDecision(decision *Decision) Outcome {
	if decision == nil {
		return Outcome{}
	}

	return Outcome{
		Allowed:           decision.Allowed,
		Matched:           decision.Policy != "",
		Policy:            decision.Policy,
		Rule:              decision.Rule,
		RequestedTLSMode:  decision.TLSMode,
		PolicyBypass:      decision.Bypass,
		PolicyEnforcement: decision.PolicyEnforcement,
	}
}

func collapseEmptyDecision(decision *Decision) *Decision {
	if decision == nil {
		return nil
	}
	if decision.Policy == "" && decision.Rule == "" && !decision.Allowed && decision.TLSMode == "" && !decision.Bypass && decision.PolicyEnforcement == "" {
		return nil
	}
	return decision
}

func isUnknownIdentity(id *identity.Identity) bool {
	return id == nil || id.Source == "unknown" || id.Name == identity.Unknown().Name
}

func connectTLSMode(requested string) string {
	if requested == "" {
		return "passthrough"
	}
	return requested
}
