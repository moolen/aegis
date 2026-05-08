package proxy

import (
	"fmt"
	"net/http"
	"net/netip"

	"github.com/moolen/aegis/internal/identity"
	"github.com/moolen/aegis/internal/policy"
)

type requestFlowTarget struct {
	Host string
	Port int
}

type requestFlowInput struct {
	Protocol string
	Request  *http.Request
	Target   *requestFlowTarget
	Identity *identity.Identity
	SourceIP netip.Addr
}

type requestFlow struct {
	protocol string
	host     string
	port     int
	sourceIP netip.Addr
	identity *identity.Identity
	outcome  policy.Outcome
	audit    auditOutcome
	action   string
	reason   string
	mode     string
	release  func()
	limitErr *ErrConnectionLimitExceeded
}

func (s *Server) evaluateRequestFlow(input requestFlowInput) (*requestFlow, error) {
	host, port, err := s.resolveRequestFlowTarget(input)
	if err != nil {
		return nil, err
	}

	flow := &requestFlow{
		protocol: input.Protocol,
		host:     host,
		port:     port,
		sourceIP: input.SourceIP,
		identity: input.Identity,
		release:  func() {},
	}
	if !flow.sourceIP.IsValid() {
		flow.sourceIP = requestSourceIP(input.Request)
	}
	if flow.identity == nil {
		flow.identity = identity.Unknown()
		if s.needsRequestIdentity() {
			flow.identity = s.resolveRequestIdentity(input.Request)
		}
	}

	policyInput := policy.EvaluateInput{
		Identity:              flow.identity,
		SourceIP:              flow.sourceIP,
		FQDN:                  flow.host,
		Port:                  flow.port,
		EnforcementMode:       EffectiveEnforcementMode(s.deps.EnforcementMode, s.deps.Enforcement),
		UnknownIdentityPolicy: s.deps.UnknownIdentityPolicy,
	}
	if input.Request != nil {
		policyInput.Method = input.Request.Method
		policyInput.Path = requestPolicyPath(input.Request)
	}

	switch input.Protocol {
	case "http", "mitm_http":
		flow.outcome = s.evaluatePolicyOutcome(input.Protocol, func() policy.Outcome {
			return policy.EvaluateHTTPOutcome(s.deps.PolicyEngine, policyInput)
		})
	case "connect":
		flow.outcome = s.evaluatePolicyOutcome("connect", func() policy.Outcome {
			return policy.EvaluateConnectOutcome(s.deps.PolicyEngine, policyInput)
		})
	default:
		return nil, fmt.Errorf("unsupported request flow protocol %q", input.Protocol)
	}

	resolvedConnectMode := ""
	if input.Protocol == "connect" {
		resolvedConnectMode = connectResolvedMode(flow.outcome)
	}

	flow.audit = auditOutcomeFromPolicyOutcome(flow.outcome)
	flow.action = flow.outcome.Action
	flow.reason = flow.outcome.Reason
	if input.Protocol == "connect" {
		flow.mode = resolvedConnectMode
	}
	if flow.action == "deny" {
		if input.Protocol == "connect" {
			flow.mode = connectDecisionMode(flow.outcome)
		}
		return flow, nil
	}
	if s.deps.PolicyEngine != nil && input.Protocol == "connect" && flow.outcome.EffectiveTLSMode == "mitm" && s.deps.MITM == nil {
		flow.action = "deny"
		flow.reason = "configuration_error"
		flow.mode = "mitm"
		return flow, nil
	}

	if input.Protocol == "connect" && flow.audit.Enabled && flow.outcome.RequestedTLSMode == "mitm" && flow.outcome.EffectiveTLSMode == "passthrough" {
		flow.audit.MITMInspectionSkipped = true
	}

	if input.Protocol != "mitm_http" {
		release, limitErr := s.acquireIdentityConnection(input.Protocol, flow.identity)
		if limitErr != nil {
			flow.action = "deny"
			flow.reason = "connection_limit_exceeded"
			flow.limitErr = limitErr
			if input.Protocol == "connect" {
				flow.mode = resolvedConnectMode
			}
			return flow, nil
		}
		flow.release = release
	}

	if flow.action == "" {
		flow.action = "allow"
		flow.reason = "policy_allowed"
	}
	if input.Protocol == "connect" {
		flow.mode = resolvedConnectMode
	}

	return flow, nil
}

func (s *Server) resolveRequestFlowTarget(input requestFlowInput) (string, int, error) {
	switch input.Protocol {
	case "http":
		if input.Target != nil && input.Target.Host != "" && input.Target.Port > 0 {
			return input.Target.Host, input.Target.Port, nil
		}
		if input.Request == nil || input.Request.URL == nil || !input.Request.URL.IsAbs() || input.Request.URL.Host == "" {
			return "", 0, fmt.Errorf("absolute target URL required")
		}
		return splitTarget(input.Request.URL.Host, input.Request.URL.Scheme)
	case "connect":
		if input.Target != nil && input.Target.Host != "" && input.Target.Port > 0 {
			return input.Target.Host, input.Target.Port, nil
		}
		target := ""
		if input.Request != nil {
			target = input.Request.Host
			if target == "" && input.Request.URL != nil {
				target = input.Request.URL.Host
			}
		}
		return splitTarget(target, "")
	case "mitm_http":
		if input.Target == nil || input.Target.Host == "" || input.Target.Port <= 0 {
			return "", 0, fmt.Errorf("missing mitm target")
		}
		return input.Target.Host, input.Target.Port, nil
	default:
		return "", 0, fmt.Errorf("unsupported request flow protocol %q", input.Protocol)
	}
}
