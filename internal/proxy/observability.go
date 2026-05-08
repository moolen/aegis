package proxy

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/moolen/aegis/internal/identity"
	"github.com/moolen/aegis/internal/policy"
)

type auditOutcome struct {
	Enabled               bool
	WouldAction           string
	WouldBlock            bool
	WouldReason           string
	EffectiveTLSMode      string
	MITMInspectionSkipped bool
	PolicyBypass          bool
}

func (s *Server) recordTLSError() {
	if s.deps.Metrics == nil {
		return
	}

	s.deps.Metrics.ErrorsTotal.WithLabelValues("tls").Inc()
}

func (s *Server) recordUpstreamTLSError(stage string) {
	if s.deps.Metrics == nil {
		return
	}
	s.deps.Metrics.UpstreamTLSErrorsTotal.WithLabelValues(stage).Inc()
}

func (s *Server) recordPolicyError() {
	if s.deps.Metrics == nil {
		return
	}

	s.deps.Metrics.ErrorsTotal.WithLabelValues("policy").Inc()
}

func (s *Server) recordConnectResult(mode string, result string) {
	if s.deps.Metrics == nil {
		return
	}

	s.deps.Metrics.ConnectTunnelsTotal.WithLabelValues(mode, result).Inc()
}

func (s *Server) recordMITMCertificateResult(result string) {
	if s.deps.Metrics == nil {
		return
	}

	s.deps.Metrics.MITMCertificatesTotal.WithLabelValues(result).Inc()
}

func (s *Server) recordRequestDecision(protocol string, action string, policyName string, reason string) {
	if s.deps.Metrics == nil {
		return
	}
	s.deps.Metrics.RequestDecisionsTotal.WithLabelValues(protocol, action, normalizePolicyName(policyName), reason).Inc()
}

func (s *Server) recordAuditDecision(protocol string, action string, reqIdentity *identity.Identity, fqdn string, policyName string, reason string) {
	if s.deps.Metrics == nil {
		return
	}
	s.deps.Metrics.AuditDecisionsTotal.WithLabelValues(
		protocol,
		action,
		normalizeIdentityName(reqIdentity),
		strings.ToLower(fqdn),
		normalizePolicyName(policyName),
		reason,
	).Inc()
}

func (s *Server) evaluatePolicyOutcome(protocol string, fn func() policy.Outcome) policy.Outcome {
	start := time.Now()
	outcome := fn()
	if s.deps.Metrics != nil {
		s.deps.Metrics.PolicyEvaluationDuration.WithLabelValues(protocol).Observe(time.Since(start).Seconds())
	}
	return outcome
}

func (s *Server) recordTLSConnectBlock(err error) {
	if s.deps.Metrics == nil {
		return
	}

	s.deps.Metrics.ErrorsTotal.WithLabelValues("tls").Inc()
	if errors.Is(err, errTLSSNIMissing) {
		s.deps.Metrics.TLSSNIMissingTotal.Inc()
	}
}

func (s *Server) logRequestDecision(level slog.Level, protocol string, action string, reason string, reqIdentity *identity.Identity, host string, port int, flow *requestFlow, method string, path string) {
	fields := []any{
		"protocol", protocol,
		"action", action,
		"reason", reason,
		"host", host,
		"port", port,
		"policy", normalizePolicyName(flow.outcome.Policy),
	}
	if method != "" {
		fields = append(fields, "method", method)
	}
	if path != "" {
		fields = append(fields, "path", path)
	}
	if flow.outcome.RequestedTLSMode != "" {
		fields = append(fields, "tls_mode", flow.outcome.RequestedTLSMode)
	}
	if flow.audit.Enabled {
		fields = append(fields,
			"audit", true,
			"would_action", flow.audit.WouldAction,
			"would_block", flow.audit.WouldBlock,
			"would_reason", flow.audit.WouldReason,
		)
		if flow.audit.EffectiveTLSMode != "" {
			fields = append(fields, "effective_tls_mode", flow.audit.EffectiveTLSMode)
		}
		if flow.audit.MITMInspectionSkipped {
			fields = append(fields, "mitm_inspection_skipped", true)
		}
		if flow.audit.PolicyBypass {
			fields = append(fields, "policy_bypass", true)
		}
	}
	if reqIdentity != nil {
		fields = append(fields,
			"identity_source", reqIdentity.Source,
			"identity_provider", reqIdentity.Provider,
			"identity_name", reqIdentity.Name,
		)
	}
	s.deps.Logger.Log(context.Background(), level, "request decision", fields...)
}

func (s *Server) logConnectionLimitExceeded(protocol string, reqIdentity *identity.Identity, host string, port int, flow *requestFlow, method string, path string, limitErr *ErrConnectionLimitExceeded) {
	fields := []any{
		"protocol", protocol,
		"action", "deny",
		"reason", "connection_limit_exceeded",
		"host", host,
		"port", port,
		"policy", normalizePolicyName(flow.outcome.Policy),
		"identity_name", normalizeIdentityName(reqIdentity),
		"active_connections", limitErr.Active,
		"connection_limit", limitErr.Limit,
	}
	if method != "" {
		fields = append(fields, "method", method)
	}
	if path != "" {
		fields = append(fields, "path", path)
	}
	if flow.outcome.RequestedTLSMode != "" {
		fields = append(fields, "tls_mode", flow.outcome.RequestedTLSMode)
	}
	s.deps.Logger.Log(context.Background(), slog.LevelWarn, "request decision", fields...)
}

func normalizePolicyName(name string) string {
	if name == "" {
		return "none"
	}
	return name
}

func normalizeIdentityName(id *identity.Identity) string {
	if id == nil || id.Name == "" {
		return identity.Unknown().Name
	}
	return id.Name
}

func isUnknownIdentity(id *identity.Identity) bool {
	return id == nil || id.Source == "unknown" || id.Name == identity.Unknown().Name
}

func auditLogLevel(audit auditOutcome) slog.Level {
	if audit.Enabled && audit.WouldBlock {
		return slog.LevelWarn
	}
	if audit.Enabled {
		return slog.LevelInfo
	}
	return slog.LevelDebug
}

func (s *Server) respondFlowDenial(w http.ResponseWriter, r *http.Request, flow *requestFlow, serverName string) bool {
	if flow.action != "deny" {
		return false
	}

	method := httpMethodForFlow(flow, r)
	path := requestPathForFlow(flow, r)
	switch flow.protocol {
	case "http":
		switch flow.reason {
		case "unknown_identity":
			s.recordRequestDecision("http", "deny", "none", "unknown_identity")
			s.logRequestDecision(slog.LevelWarn, "http", "deny", "unknown_identity", flow.identity, flow.host, flow.port, flow, method, path)
			s.writeError(w, http.StatusForbidden, "request denied for unknown identity", "identity")
		case "policy_denied":
			s.recordRequestDecision("http", "deny", flow.outcome.Policy, "policy_denied")
			s.logRequestDecision(slog.LevelWarn, "http", "deny", "policy_denied", flow.identity, flow.host, flow.port, flow, method, path)
			s.writeError(w, http.StatusForbidden, "request denied by policy", "policy")
		case "connection_limit_exceeded":
			s.recordRequestDecision("http", "deny", flow.outcome.Policy, "connection_limit_exceeded")
			s.logConnectionLimitExceeded("http", flow.identity, flow.host, flow.port, flow, method, path, flow.limitErr)
			s.writeError(w, http.StatusTooManyRequests, "identity concurrent connection limit exceeded", "limits")
		default:
			s.writeError(w, http.StatusInternalServerError, "internal proxy error", "server")
		}
	case "connect":
		switch flow.reason {
		case "unknown_identity":
			s.recordConnectResult(flow.mode, "unknown_identity")
			s.recordRequestDecision("connect", "deny", "none", "unknown_identity")
			s.logRequestDecision(slog.LevelWarn, "connect", "deny", "unknown_identity", flow.identity, flow.host, flow.port, flow, method, path)
			s.writeError(w, http.StatusForbidden, "connect target denied for unknown identity", "identity")
		case "policy_denied":
			s.recordConnectResult(flow.mode, "policy_denied")
			s.recordRequestDecision("connect", "deny", flow.outcome.Policy, "policy_denied")
			s.logRequestDecision(slog.LevelWarn, "connect", "deny", "policy_denied", flow.identity, flow.host, flow.port, flow, method, path)
			s.writeError(w, http.StatusForbidden, "connect target denied by policy", "policy")
		case "configuration_error":
			s.recordConnectResult(flow.mode, "configuration_error")
			s.writeError(w, http.StatusInternalServerError, "connect tls mitm requires proxy.ca cert and key configuration", "tls")
		case "connection_limit_exceeded":
			s.recordConnectResult(flow.mode, "connection_limit_exceeded")
			s.recordRequestDecision("connect", "deny", flow.outcome.Policy, "connection_limit_exceeded")
			s.logConnectionLimitExceeded("connect", flow.identity, flow.host, flow.port, flow, method, path, flow.limitErr)
			s.writeError(w, http.StatusTooManyRequests, "identity concurrent connection limit exceeded", "limits")
		default:
			s.recordConnectResult(flow.mode, "server_error")
			s.writeError(w, http.StatusInternalServerError, "internal proxy error", "server")
		}
	case "mitm_http":
		switch flow.reason {
		case "policy_denied":
			s.recordRequestDecision("mitm_http", "deny", flow.outcome.Policy, "policy_denied")
			s.logRequestDecision(slog.LevelWarn, "mitm_http", "deny", "policy_denied", flow.identity, flow.host, flow.port, flow, method, path)
			s.deps.Logger.Warn("connect mitm request denied by policy", "server_name", serverName, "method", method, "path", path)
			http.Error(w, "request denied by policy", http.StatusForbidden)
		default:
			http.Error(w, "internal proxy error", http.StatusInternalServerError)
		}
	default:
		s.writeError(w, http.StatusInternalServerError, "internal proxy error", "server")
	}

	return true
}

func (s *Server) observeAllowedRequestFlow(r *http.Request, flow *requestFlow) {
	s.recordRequestDecision(flow.protocol, "allow", flow.outcome.Policy, flow.reason)
	if flow.audit.Enabled {
		s.recordAuditDecision(flow.protocol, flow.audit.WouldAction, flow.identity, flow.host, flow.outcome.Policy, flow.audit.WouldReason)
	}
	s.logRequestDecision(auditLogLevel(flow.audit), flow.protocol, "allow", flow.reason, flow.identity, flow.host, flow.port, flow, httpMethodForFlow(flow, r), requestPathForFlow(flow, r))
}

func (s *Server) observeHTTPDestinationBlocked(r *http.Request, flow *requestFlow, err error) {
	s.recordRequestDecision("http", "deny", flow.outcome.Policy, "destination_blocked")
	s.logRequestDecision(slog.LevelWarn, "http", "deny", "destination_blocked", flow.identity, flow.host, flow.port, flow, r.Method, requestPolicyPath(r))
	s.deps.Logger.Warn("http destination blocked", "host", flow.host, "port", flow.port, "error", err)
}

func (s *Server) observeHTTPDNSError(flow *requestFlow, err error) {
	s.deps.Logger.Warn("http target resolution failed", "host", flow.host, "port", flow.port, "error", err)
}

func (s *Server) observeHTTPDialError(flow *requestFlow, targetAddr string, err error) {
	s.deps.Logger.Warn("http upstream round trip failed", "host", flow.host, "port", flow.port, "target_addr", targetAddr, "error", err)
}

func (s *Server) observeConnectEstablished(flow *requestFlow) {
	s.recordConnectResult(flow.mode, "established")
}

func (s *Server) observeConnectDestinationBlocked(flow *requestFlow, err error) {
	s.recordConnectResult(flow.mode, "destination_blocked")
	s.recordRequestDecision("connect", "deny", flow.outcome.Policy, "destination_blocked")
	s.logRequestDecision(slog.LevelWarn, "connect", "deny", "destination_blocked", flow.identity, flow.host, flow.port, flow, http.MethodConnect, "")
	s.deps.Logger.Warn("connect destination blocked", "host", flow.host, "port", flow.port, "error", err)
}

func (s *Server) observeConnectDNSError(flow *requestFlow, err error) {
	s.recordConnectResult(flow.mode, "dns_error")
	s.deps.Logger.Warn("connect target resolution failed", "host", flow.host, "port", flow.port, "error", err)
}

func (s *Server) observeConnectDialError(flow *requestFlow, targetAddr string, err error) {
	s.recordConnectResult(flow.mode, "upstream_dial_error")
	s.deps.Logger.Warn("connect upstream dial failed", "host", flow.host, "port", flow.port, "target_addr", targetAddr, "error", err)
}

func (s *Server) observeConnectServerError(mode string, message string, err error) {
	s.recordConnectResult(mode, "server_error")
	if err != nil {
		s.deps.Logger.Error(message, "error", err)
		return
	}
	s.deps.Logger.Error(message)
}

func (s *Server) observeConnectTLSInspectionError(flow *requestFlow, err error) {
	s.recordConnectResult(flow.mode, "tls_blocked")
	s.recordTLSConnectBlock(err)
	s.deps.Logger.Warn("connect tls inspection failed", "target", flow.host, "error", err)
}

func (s *Server) observeConnectTLSMismatch(flow *requestFlow, sni string) {
	s.recordConnectResult(flow.mode, "tls_blocked")
	s.recordTLSConnectBlock(nil)
	s.deps.Logger.Warn("connect tls sni mismatch", "target", flow.host, "sni", sni)
}

func (s *Server) observeConnectTLSForwardError(flow *requestFlow) {
	s.recordConnectResult(flow.mode, "tls_blocked")
}

func (s *Server) observeMITMFlowEvaluationError(serverName string, err error) {
	s.recordPolicyError()
	s.deps.Logger.Error("connect mitm request flow evaluation failed", "server_name", serverName, "error", err)
}

func (s *Server) observeMITMClientHandshakeError(serverName string, err error) {
	s.recordConnectResult("mitm", "client_tls_error")
	s.recordTLSError()
	s.deps.Logger.Warn("connect mitm client handshake failed", "server_name", serverName, "error", err)
}

func (s *Server) observeMITMEstablished() {
	s.recordConnectResult("mitm", "established")
}

func (s *Server) observeMITMCertificateResult(result string) {
	s.recordMITMCertificateResult(result)
}

func (s *Server) observeMITMServeError(serverName string, err error) {
	s.recordTLSError()
	s.deps.Logger.Warn("connect mitm serve failed", "server_name", serverName, "error", err)
}

func (s *Server) observeMITMUpstreamError(flow *requestFlow, err error) {
	s.recordTLSError()
	if isUpstreamTLSHandshakeError(err) {
		s.observeUpstreamTLSHandshakeError()
	}
	s.deps.Logger.Warn("connect mitm upstream round trip failed", "server_name", flow.host, "error", err)
}

func (s *Server) observeMITMWriteClientError(flow *requestFlow, err error) {
	s.recordTLSError()
	s.deps.Logger.Warn("connect mitm write client response failed", "server_name", flow.host, "error", err)
}

func (s *Server) observeUpstreamTLSHandshakeError() {
	s.recordUpstreamTLSError("handshake")
}

func auditOutcomeFromPolicyOutcome(outcome policy.Outcome) auditOutcome {
	if !outcome.Audit.Enabled {
		return auditOutcome{}
	}
	return auditOutcome{
		Enabled:               true,
		WouldAction:           outcome.Audit.WouldAction,
		WouldBlock:            outcome.Audit.WouldBlock,
		WouldReason:           outcome.Audit.WouldReason,
		EffectiveTLSMode:      outcome.EffectiveTLSMode,
		MITMInspectionSkipped: false,
		PolicyBypass:          outcome.Audit.PolicyBypass,
	}
}

func httpMethodForFlow(flow *requestFlow, r *http.Request) string {
	if flow.protocol == "connect" {
		return http.MethodConnect
	}
	if r == nil {
		return ""
	}
	return r.Method
}

func requestPathForFlow(flow *requestFlow, r *http.Request) string {
	if flow.protocol == "connect" || r == nil {
		return ""
	}
	return requestPolicyPath(r)
}
