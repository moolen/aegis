package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/textproto"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/moolen/aegis/internal/config"
	"github.com/moolen/aegis/internal/identity"
	"github.com/moolen/aegis/internal/metrics"
	"github.com/moolen/aegis/internal/policy"
)

type Resolver interface {
	LookupNetIP(context.Context, string) ([]net.IP, error)
}

type IdentityResolver interface {
	Resolve(net.IP) (*identity.Identity, error)
}

type PolicyEngine interface {
	Evaluate(id *identity.Identity, sourceIP netip.Addr, fqdn string, port int, method string, path string) *policy.Decision
	EvaluateConnect(id *identity.Identity, sourceIP netip.Addr, fqdn string, port int) *policy.Decision
}

type Dependencies struct {
	Resolver              Resolver
	DestinationGuard      *DestinationGuard
	DrainTracker          *DrainTracker
	ConnectionLimiter     *ConnectionLimiter
	UpstreamHTTPTransport *http.Transport
	EnforcementMode       string
	Enforcement           *EnforcementOverrideController
	UnknownIdentityPolicy string
	IdentityResolver      IdentityResolver
	PolicyEngine          PolicyEngine
	MITM                  *MITMEngine
	UpstreamTLSConfig     *tls.Config
	Metrics               *metrics.Metrics
	Logger                *slog.Logger
}

type Server struct {
	deps Dependencies
}

type auditOutcome struct {
	Enabled               bool
	WouldAction           string
	WouldBlock            bool
	WouldReason           string
	EffectiveTLSMode      string
	MITMInspectionSkipped bool
	PolicyBypass          bool
}

func NewServer(deps Dependencies) *Server {
	if deps.Logger == nil {
		deps.Logger = slog.Default()
	}
	if deps.UpstreamHTTPTransport == nil {
		deps.UpstreamHTTPTransport = NewUpstreamHTTPTransport()
	}
	return &Server{deps: deps}
}

func NewUpstreamHTTPTransport() *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.MaxIdleConns = 1024
	transport.MaxIdleConnsPerHost = 256
	transport.MaxConnsPerHost = 0
	transport.IdleConnTimeout = 90 * time.Second
	return transport
}

func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(s.handle)
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	protocol := "http"
	if r.Method == http.MethodConnect {
		protocol = "connect"
	}

	if s.deps.Metrics != nil {
		defer s.deps.Metrics.RequestDuration.WithLabelValues(r.Method, protocol).Observe(time.Since(start).Seconds())
		s.deps.Metrics.RequestsTotal.WithLabelValues(r.Method, protocol).Inc()
	}

	if r.Method == http.MethodConnect {
		s.handleConnect(w, r)
		return
	}

	s.handleHTTP(w, r)
}

func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL == nil || !r.URL.IsAbs() || r.URL.Host == "" {
		s.writeError(w, http.StatusBadRequest, "absolute target URL required", "request")
		return
	}

	host, port, err := splitTarget(r.URL.Host, r.URL.Scheme)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error(), "request")
		return
	}

	reqIdentity := identity.Unknown()
	sourceIP := requestSourceIP(r)
	var decision *policy.Decision
	audit := auditOutcome{}
	if s.needsRequestIdentity() {
		reqIdentity = s.resolveRequestIdentity(r)
	}
	if s.deps.PolicyEngine != nil {
		decision = s.evaluatePolicy("http", func() *policy.Decision {
			return s.deps.PolicyEngine.Evaluate(reqIdentity, sourceIP, host, port, r.Method, requestPolicyPath(r))
		})
	}
	if s.denyUnknownIdentity(reqIdentity) && decision == nil {
		audit = s.recordUnknownIdentityAuditDecision("http", reqIdentity, host)
		if !audit.Enabled {
			s.recordRequestDecision("http", "deny", "none", "unknown_identity")
			s.logRequestDecision(slog.LevelWarn, "http", "deny", "unknown_identity", reqIdentity, host, port, nil, r.Method, requestPolicyPath(r), auditOutcome{})
			s.writeError(w, http.StatusForbidden, "request denied for unknown identity", "identity")
			return
		}
	} else if s.deps.PolicyEngine != nil {
		audit = s.recordAuditPolicyDecision("http", reqIdentity, host, decision)
		if !s.shadowMode(decision) && (decision == nil || !decision.Allowed) {
			s.recordRequestDecision("http", "deny", decisionPolicyName(decision), "policy_denied")
			s.logRequestDecision(slog.LevelWarn, "http", "deny", "policy_denied", reqIdentity, host, port, decision, r.Method, requestPolicyPath(r), auditOutcome{})
			s.writeError(w, http.StatusForbidden, "request denied by policy", "policy")
			return
		}
	}
	releaseConnectionLimit, limitErr := s.acquireIdentityConnection("http", reqIdentity)
	if limitErr != nil {
		s.recordRequestDecision("http", "deny", decisionPolicyName(decision), "connection_limit_exceeded")
		s.logConnectionLimitExceeded("http", reqIdentity, host, port, decision, r.Method, requestPolicyPath(r), limitErr)
		s.writeError(w, http.StatusTooManyRequests, "identity concurrent connection limit exceeded", "limits")
		return
	}
	defer releaseConnectionLimit()

	targetAddr, err := s.resolveAddr(r.Context(), host, port)
	if err != nil {
		if IsDestinationBlocked(err) {
			s.recordRequestDecision("http", "deny", decisionPolicyName(decision), "destination_blocked")
			s.logRequestDecision(slog.LevelWarn, "http", "deny", "destination_blocked", reqIdentity, host, port, decision, r.Method, requestPolicyPath(r), audit)
			s.writeError(w, http.StatusForbidden, err.Error(), "destination")
			return
		}
		s.writeError(w, http.StatusBadGateway, err.Error(), "dns")
		return
	}
	reason := "policy_allowed"
	if audit.Enabled {
		reason = auditActualReason(audit)
	}
	s.recordRequestDecision("http", "allow", decisionPolicyName(decision), reason)
	s.logRequestDecision(auditLogLevel(audit), "http", "allow", reason, reqIdentity, host, port, decision, r.Method, requestPolicyPath(r), audit)

	outReq := r.Clone(r.Context())
	outReq.RequestURI = ""
	outReq.Host = r.Host
	outReq.URL.Host = targetAddr
	removeHopByHopHeaders(outReq.Header)

	resp, err := s.deps.UpstreamHTTPTransport.RoundTrip(outReq)
	if err != nil {
		s.writeError(w, http.StatusBadGateway, fmt.Sprintf("upstream round trip failed: %v", err), "dial")
		return
	}
	defer resp.Body.Close()

	removeHopByHopHeaders(resp.Header)
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		s.deps.Logger.Error("copy upstream response failed", "error", err)
	}
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	target := r.Host
	if target == "" && r.URL != nil {
		target = r.URL.Host
	}
	host, port, err := splitTarget(target, "")
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error(), "request")
		return
	}

	reqIdentity := identity.Unknown()
	sourceIP := requestSourceIP(r)
	var decision *policy.Decision
	audit := auditOutcome{}
	if s.needsRequestIdentity() {
		reqIdentity = s.resolveRequestIdentity(r)
	}
	if s.deps.PolicyEngine != nil {
		decision = s.evaluatePolicy("connect", func() *policy.Decision {
			return s.deps.PolicyEngine.EvaluateConnect(reqIdentity, sourceIP, host, port)
		})
	}
	if s.denyUnknownIdentity(reqIdentity) && decision == nil {
		audit = s.recordUnknownIdentityAuditDecision("connect", reqIdentity, host)
		if !audit.Enabled {
			s.recordConnectResult("passthrough", "unknown_identity")
			s.recordRequestDecision("connect", "deny", "none", "unknown_identity")
			s.logRequestDecision(slog.LevelWarn, "connect", "deny", "unknown_identity", reqIdentity, host, port, nil, http.MethodConnect, "", auditOutcome{})
			s.writeError(w, http.StatusForbidden, "connect target denied for unknown identity", "identity")
			return
		}
	} else if s.deps.PolicyEngine != nil {
		audit = s.recordAuditPolicyDecision("connect", reqIdentity, host, decision)
		if !s.shadowMode(decision) && (decision == nil || !decision.Allowed) {
			s.recordConnectResult(connectDecisionMode(decision), "policy_denied")
			s.recordRequestDecision("connect", "deny", decisionPolicyName(decision), "policy_denied")
			s.logRequestDecision(slog.LevelWarn, "connect", "deny", "policy_denied", reqIdentity, host, port, decision, http.MethodConnect, "", auditOutcome{})
			s.writeError(w, http.StatusForbidden, "connect target denied by policy", "policy")
			return
		}
		if !s.shadowMode(decision) && decision.TLSMode == "mitm" && s.deps.MITM == nil {
			s.recordConnectResult("mitm", "configuration_error")
			s.writeError(w, http.StatusInternalServerError, "connect tls mitm requires proxy.ca cert and key configuration", "tls")
			return
		}
	}

	mode := connectResolvedMode(decision)
	if s.shadowMode(decision) {
		mode = "passthrough"
		if decision != nil && decision.TLSMode == "mitm" {
			audit.MITMInspectionSkipped = true
			audit.EffectiveTLSMode = "passthrough"
		}
	}
	releaseConnectionLimit, limitErr := s.acquireIdentityConnection("connect", reqIdentity)
	if limitErr != nil {
		s.recordConnectResult(mode, "connection_limit_exceeded")
		s.recordRequestDecision("connect", "deny", decisionPolicyName(decision), "connection_limit_exceeded")
		s.logConnectionLimitExceeded("connect", reqIdentity, host, port, decision, http.MethodConnect, "", limitErr)
		s.writeError(w, http.StatusTooManyRequests, "identity concurrent connection limit exceeded", "limits")
		return
	}
	defer releaseConnectionLimit()

	targetAddr, err := s.resolveAddr(r.Context(), host, port)
	if err != nil {
		if IsDestinationBlocked(err) {
			s.recordConnectResult(mode, "destination_blocked")
			s.recordRequestDecision("connect", "deny", decisionPolicyName(decision), "destination_blocked")
			s.logRequestDecision(slog.LevelWarn, "connect", "deny", "destination_blocked", reqIdentity, host, port, decision, http.MethodConnect, "", audit)
			s.writeError(w, http.StatusForbidden, err.Error(), "destination")
			return
		}
		s.recordConnectResult(mode, "dns_error")
		s.writeError(w, http.StatusBadGateway, err.Error(), "dns")
		return
	}

	upstreamConn, err := (&net.Dialer{}).DialContext(r.Context(), "tcp", targetAddr)
	if err != nil {
		s.recordConnectResult(mode, "upstream_dial_error")
		s.writeError(w, http.StatusBadGateway, fmt.Sprintf("connect upstream failed: %v", err), "dial")
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		s.recordConnectResult(mode, "server_error")
		upstreamConn.Close()
		s.writeError(w, http.StatusInternalServerError, "response writer does not support hijacking", "server")
		return
	}

	clientConn, buf, err := hijacker.Hijack()
	if err != nil {
		s.recordConnectResult(mode, "server_error")
		upstreamConn.Close()
		s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("hijack failed: %v", err), "server")
		return
	}

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		clientConn.Close()
		upstreamConn.Close()
		return
	}
	releaseTunnel := s.trackConnectTunnel(mode, clientConn, upstreamConn)
	defer releaseTunnel()

	if s.shadowMode(decision) {
		s.recordConnectResult(mode, "established")
		reason := auditActualReason(audit)
		s.recordRequestDecision("connect", "allow", decisionPolicyName(decision), reason)
		s.logRequestDecision(auditLogLevel(audit), "connect", "allow", reason, reqIdentity, host, port, decision, http.MethodConnect, "", audit)
		s.spliceConnectTunnel(clientConn, upstreamConn, buf.Reader)
		return
	}

	if err := clientConn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		s.deps.Logger.Debug("set connect client read deadline failed", "error", err)
	}
	clientHello, sni, err := readClientHello(buf.Reader)
	_ = clientConn.SetReadDeadline(time.Time{})
	if err != nil {
		s.recordConnectResult(mode, "tls_blocked")
		s.recordTLSConnectBlock(err)
		s.deps.Logger.Warn("connect tls inspection failed", "target", host, "error", err)
		clientConn.Close()
		upstreamConn.Close()
		return
	}
	if !strings.EqualFold(sni, host) {
		s.recordConnectResult(mode, "tls_blocked")
		s.recordTLSConnectBlock(nil)
		s.deps.Logger.Warn("connect tls sni mismatch", "target", host, "sni", sni)
		clientConn.Close()
		upstreamConn.Close()
		return
	}

	if decision != nil && decision.TLSMode == "mitm" {
		s.recordRequestDecision("connect", "allow", decisionPolicyName(decision), "policy_allowed")
		s.logRequestDecision(slog.LevelInfo, "connect", "allow", "policy_allowed", reqIdentity, host, port, decision, http.MethodConnect, "", audit)
		s.handleConnectMITM(clientConn, buf.Reader, clientHello, upstreamConn, reqIdentity, sourceIP, sni, port)
		return
	}

	if _, err := upstreamConn.Write(clientHello); err != nil {
		s.recordConnectResult(mode, "tls_blocked")
		clientConn.Close()
		upstreamConn.Close()
		return
	}

	s.recordConnectResult(mode, "established")
	reason := "policy_allowed"
	if audit.Enabled {
		reason = auditActualReason(audit)
	}
	s.recordRequestDecision("connect", "allow", decisionPolicyName(decision), reason)
	s.logRequestDecision(auditLogLevel(audit), "connect", "allow", reason, reqIdentity, host, port, decision, http.MethodConnect, "", audit)
	s.spliceConnectTunnel(clientConn, upstreamConn, buf.Reader)
}

func (s *Server) handleConnectMITM(clientConn net.Conn, clientReader *bufio.Reader, clientHello []byte, upstreamConn net.Conn, reqIdentity *identity.Identity, sourceIP netip.Addr, serverName string, port int) {
	clientTLSConn, err := s.handshakeClientMITM(clientConn, clientReader, clientHello, serverName)
	if err != nil {
		s.recordConnectResult("mitm", "client_tls_error")
		s.recordTLSError()
		s.deps.Logger.Warn("connect mitm client handshake failed", "server_name", serverName, "error", err)
		clientConn.Close()
		upstreamConn.Close()
		return
	}
	defer clientTLSConn.Close()

	upstreamTLSConn, err := s.handshakeUpstreamTLS(upstreamConn, serverName)
	if err != nil {
		s.recordConnectResult("mitm", "upstream_tls_error")
		s.recordTLSError()
		s.deps.Logger.Warn("connect mitm upstream handshake failed", "server_name", serverName, "error", err)
		return
	}
	defer upstreamTLSConn.Close()

	s.recordConnectResult("mitm", "established")

	clientReaderTLS := bufio.NewReader(clientTLSConn)
	upstreamReaderTLS := bufio.NewReader(upstreamTLSConn)

	for {
		req, err := http.ReadRequest(clientReaderTLS)
		if err != nil {
			if isConnectionClosed(err) {
				return
			}
			s.recordTLSError()
			s.deps.Logger.Warn("connect mitm read request failed", "server_name", serverName, "error", err)
			return
		}

		if s.deps.PolicyEngine != nil {
			decision := s.evaluatePolicy("mitm_http", func() *policy.Decision {
				return s.deps.PolicyEngine.Evaluate(reqIdentity, sourceIP, serverName, port, req.Method, requestPolicyPath(req))
			})
			audit := s.recordAuditPolicyDecision("mitm_http", reqIdentity, serverName, decision)
			if !s.shadowMode(decision) && (decision == nil || !decision.Allowed) {
				s.recordPolicyError()
				s.recordRequestDecision("mitm_http", "deny", decisionPolicyName(decision), "policy_denied")
				s.logRequestDecision(slog.LevelWarn, "mitm_http", "deny", "policy_denied", reqIdentity, serverName, port, decision, req.Method, requestPolicyPath(req), auditOutcome{})
				s.deps.Logger.Warn("connect mitm request denied by policy", "server_name", serverName, "method", req.Method, "path", requestPolicyPath(req))
				_ = writeMITMErrorResponse(clientTLSConn, http.StatusForbidden, "request denied by policy")
				return
			}
			reason := "policy_allowed"
			if audit.Enabled {
				reason = auditActualReason(audit)
			}
			s.recordRequestDecision("mitm_http", "allow", decisionPolicyName(decision), reason)
			s.logRequestDecision(auditLogLevel(audit), "mitm_http", "allow", reason, reqIdentity, serverName, port, decision, req.Method, requestPolicyPath(req), audit)
		}

		req.RequestURI = ""
		removeHopByHopHeaders(req.Header)
		if err := req.Write(upstreamTLSConn); err != nil {
			s.recordTLSError()
			s.deps.Logger.Warn("connect mitm write upstream request failed", "server_name", serverName, "error", err)
			_ = writeMITMErrorResponse(clientTLSConn, http.StatusBadGateway, "upstream request failed")
			return
		}

		resp, err := http.ReadResponse(upstreamReaderTLS, req)
		if err != nil {
			s.recordTLSError()
			s.deps.Logger.Warn("connect mitm read upstream response failed", "server_name", serverName, "error", err)
			_ = writeMITMErrorResponse(clientTLSConn, http.StatusBadGateway, "upstream response failed")
			return
		}

		if err := resp.Write(clientTLSConn); err != nil {
			resp.Body.Close()
			if isConnectionClosed(err) {
				return
			}
			s.recordTLSError()
			s.deps.Logger.Warn("connect mitm write client response failed", "server_name", serverName, "error", err)
			return
		}
		resp.Body.Close()
	}
}

func (s *Server) handshakeClientMITM(clientConn net.Conn, clientReader *bufio.Reader, clientHello []byte, serverName string) (*tls.Conn, error) {
	certificate, result, err := s.deps.MITM.CertificateForSNI(serverName)
	if err != nil {
		s.recordMITMCertificateResult("error")
		return nil, err
	}
	s.recordMITMCertificateResult(result)

	tlsConn := tls.Server(&replayConn{
		Conn:   clientConn,
		reader: io.MultiReader(bytes.NewReader(clientHello), clientReader),
	}, &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{*certificate},
	})
	if err := tlsConn.Handshake(); err != nil {
		return nil, err
	}

	return tlsConn, nil
}

func (s *Server) handshakeUpstreamTLS(upstreamConn net.Conn, serverName string) (*tls.Conn, error) {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: serverName,
	}
	if s.deps.UpstreamTLSConfig != nil {
		cfg = s.deps.UpstreamTLSConfig.Clone()
		cfg.ServerName = serverName
		if cfg.MinVersion == 0 {
			cfg.MinVersion = tls.VersionTLS12
		}
	}

	tlsConn := tls.Client(upstreamConn, cfg)
	if err := tlsConn.Handshake(); err != nil {
		s.recordUpstreamTLSError("handshake")
		upstreamConn.Close()
		return nil, err
	}

	return tlsConn, nil
}

func (s *Server) spliceConnectTunnel(clientConn net.Conn, upstreamConn net.Conn, clientReader io.Reader) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, _ = io.Copy(upstreamConn, clientReader)
		_ = upstreamConn.Close()
	}()

	go func() {
		defer wg.Done()
		_, _ = io.Copy(clientConn, upstreamConn)
		_ = clientConn.Close()
	}()

	wg.Wait()
}

func (s *Server) recordTLSError() {
	if s.deps.Metrics == nil {
		return
	}

	s.deps.Metrics.ErrorsTotal.WithLabelValues("tls").Inc()
}

func (s *Server) trackConnectTunnel(mode string, closers ...io.Closer) func() {
	if s.deps.DrainTracker == nil {
		return func() {}
	}
	return s.deps.DrainTracker.Track(mode, closers...)
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

func (s *Server) evaluatePolicy(protocol string, fn func() *policy.Decision) *policy.Decision {
	start := time.Now()
	decision := fn()
	if s.deps.Metrics != nil {
		s.deps.Metrics.PolicyEvaluationDuration.WithLabelValues(protocol).Observe(time.Since(start).Seconds())
	}
	return decision
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

func (s *Server) resolveRequestIdentity(r *http.Request) *identity.Identity {
	reqIdentity := identity.Unknown()
	if s.deps.IdentityResolver == nil {
		return reqIdentity
	}

	sourceIP := requestSourceIP(r)
	if !sourceIP.IsValid() {
		return reqIdentity
	}

	remoteIP := net.IP(sourceIP.AsSlice())
	resolvedIdentity, err := s.deps.IdentityResolver.Resolve(remoteIP)
	if err != nil {
		s.deps.Logger.Debug("resolve request identity failed", "remote_ip", remoteIP.String(), "error", err)
		return reqIdentity
	}
	if resolvedIdentity == nil {
		return reqIdentity
	}

	return resolvedIdentity
}

func requestSourceIP(r *http.Request) netip.Addr {
	if r == nil {
		return netip.Addr{}
	}

	remoteHost, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}

	addr, err := netip.ParseAddr(remoteHost)
	if err != nil {
		return netip.Addr{}
	}

	return addr.Unmap()
}

func (s *Server) needsRequestIdentity() bool {
	return s.deps.PolicyEngine != nil ||
		(s.deps.ConnectionLimiter != nil && s.deps.ConnectionLimiter.Enabled()) ||
		config.NormalizeUnknownIdentityPolicy(s.deps.UnknownIdentityPolicy) == config.UnknownIdentityDeny
}

func (s *Server) acquireIdentityConnection(protocol string, reqIdentity *identity.Identity) (func(), *ErrConnectionLimitExceeded) {
	if s.deps.ConnectionLimiter == nil {
		return func() {}, nil
	}

	release, err := s.deps.ConnectionLimiter.Acquire(reqIdentity, protocol)
	if err == nil {
		return release, nil
	}

	var limitErr *ErrConnectionLimitExceeded
	if errors.As(err, &limitErr) {
		return nil, limitErr
	}

	s.deps.Logger.Error("identity connection limiter failed", "protocol", protocol, "identity_name", normalizeIdentityName(reqIdentity), "error", err)
	return nil, &ErrConnectionLimitExceeded{
		Identity: normalizeIdentityName(reqIdentity),
	}
}

func requestPolicyPath(r *http.Request) string {
	if r.URL == nil {
		return "/"
	}

	reqPath := r.URL.EscapedPath()
	if reqPath == "" {
		return "/"
	}

	return reqPath
}

func (s *Server) resolveAddr(ctx context.Context, host string, port int) (string, error) {
	if ip := net.ParseIP(host); ip != nil {
		if s.deps.DestinationGuard != nil {
			if err := s.deps.DestinationGuard.ValidateDirectIP(host, ip); err != nil {
				return "", err
			}
		}
		return net.JoinHostPort(ip.String(), strconv.Itoa(port)), nil
	}
	if s.deps.Resolver == nil {
		return "", fmt.Errorf("no resolver configured")
	}

	ips, err := s.deps.Resolver.LookupNetIP(ctx, host)
	if err != nil {
		return "", err
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("no IPs returned for %s", host)
	}
	selectedIP := ips[0]
	if s.deps.DestinationGuard != nil {
		selectedIP, err = s.deps.DestinationGuard.SelectResolvedIP(host, ips)
		if err != nil {
			return "", err
		}
	}

	return net.JoinHostPort(selectedIP.String(), strconv.Itoa(port)), nil
}

func (s *Server) writeError(w http.ResponseWriter, status int, message string, stage string) {
	if s.deps.Metrics != nil {
		s.deps.Metrics.ErrorsTotal.WithLabelValues(stage).Inc()
	}
	http.Error(w, message, status)
}

func splitTarget(hostport string, scheme string) (string, int, error) {
	if hostport == "" {
		return "", 0, fmt.Errorf("missing target host")
	}

	if strings.Contains(hostport, ":") {
		host, portStr, err := net.SplitHostPort(hostport)
		if err == nil {
			port, convErr := strconv.Atoi(portStr)
			if convErr != nil {
				return "", 0, fmt.Errorf("invalid port %q", portStr)
			}
			return host, port, nil
		}
	}

	switch scheme {
	case "http":
		return hostport, 80, nil
	case "https":
		return hostport, 443, nil
	case "":
		return "", 0, fmt.Errorf("missing target port")
	default:
		return "", 0, fmt.Errorf("unsupported scheme %q", scheme)
	}
}

func copyHeader(dst, src http.Header) {
	for key, values := range src {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func removeHopByHopHeaders(header http.Header) {
	for _, key := range connectionHeaderTokens(header.Values("Connection")) {
		header.Del(key)
	}
	for _, key := range connectionHeaderTokens(header.Values("Proxy-Connection")) {
		header.Del(key)
	}
	for _, key := range []string{
		"Connection",
		"Proxy-Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Te",
		"Trailer",
		"Transfer-Encoding",
		"Upgrade",
	} {
		header.Del(key)
	}
}

func connectionHeaderTokens(values []string) []string {
	if len(values) == 0 {
		return nil
	}

	tokens := make([]string, 0, len(values))
	for _, value := range values {
		for _, token := range strings.Split(value, ",") {
			token = textproto.CanonicalMIMEHeaderKey(strings.TrimSpace(token))
			if token == "" {
				continue
			}
			tokens = append(tokens, token)
		}
	}
	return tokens
}

type replayConn struct {
	net.Conn
	reader io.Reader
}

func (c *replayConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func writeMITMErrorResponse(w io.Writer, status int, message string) error {
	body := message + "\n"
	resp := &http.Response{
		StatusCode:    status,
		Status:        fmt.Sprintf("%d %s", status, http.StatusText(status)),
		ProtoMajor:    1,
		ProtoMinor:    1,
		ContentLength: int64(len(body)),
		Header: http.Header{
			"Content-Length": []string{strconv.Itoa(len(body))},
			"Content-Type":   []string{"text/plain; charset=utf-8"},
			"Connection":     []string{"close"},
		},
		Body: io.NopCloser(strings.NewReader(body)),
	}

	return resp.Write(w)
}

func isConnectionClosed(err error) bool {
	return err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed)
}

func connectDecisionMode(decision *policy.Decision) string {
	if decision == nil || decision.TLSMode == "" {
		return "unknown"
	}
	return decision.TLSMode
}

func connectResolvedMode(decision *policy.Decision) string {
	if decision == nil || decision.TLSMode == "" {
		return "passthrough"
	}
	return decision.TLSMode
}

func (s *Server) logRequestDecision(level slog.Level, protocol string, action string, reason string, reqIdentity *identity.Identity, host string, port int, decision *policy.Decision, method string, path string, audit auditOutcome) {
	fields := []any{
		"protocol", protocol,
		"action", action,
		"reason", reason,
		"host", host,
		"port", port,
		"policy", normalizePolicyName(decisionPolicyName(decision)),
	}
	if method != "" {
		fields = append(fields, "method", method)
	}
	if path != "" {
		fields = append(fields, "path", path)
	}
	if decision != nil && decision.TLSMode != "" {
		fields = append(fields, "tls_mode", decision.TLSMode)
	}
	if audit.Enabled {
		fields = append(fields,
			"audit", true,
			"would_action", audit.WouldAction,
			"would_block", audit.WouldBlock,
			"would_reason", audit.WouldReason,
		)
		if audit.EffectiveTLSMode != "" {
			fields = append(fields, "effective_tls_mode", audit.EffectiveTLSMode)
		}
		if audit.MITMInspectionSkipped {
			fields = append(fields, "mitm_inspection_skipped", true)
		}
		if audit.PolicyBypass {
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

func (s *Server) logConnectionLimitExceeded(protocol string, reqIdentity *identity.Identity, host string, port int, decision *policy.Decision, method string, path string, limitErr *ErrConnectionLimitExceeded) {
	fields := []any{
		"protocol", protocol,
		"action", "deny",
		"reason", "connection_limit_exceeded",
		"host", host,
		"port", port,
		"policy", normalizePolicyName(decisionPolicyName(decision)),
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
	if decision != nil && decision.TLSMode != "" {
		fields = append(fields, "tls_mode", decision.TLSMode)
	}
	s.deps.Logger.Log(context.Background(), slog.LevelWarn, "request decision", fields...)
}

func decisionPolicyName(decision *policy.Decision) string {
	if decision == nil {
		return ""
	}
	return decision.Policy
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

func (s *Server) auditMode() bool {
	return IsAuditMode(s.deps.EnforcementMode, s.deps.Enforcement)
}

func (s *Server) shadowMode(decision *policy.Decision) bool {
	return s.auditMode() || (decision != nil && (decision.Bypass || decision.PolicyEnforcement == config.EnforcementAudit))
}

func (s *Server) recordAuditPolicyDecision(protocol string, reqIdentity *identity.Identity, fqdn string, decision *policy.Decision) auditOutcome {
	if !s.shadowMode(decision) {
		return auditOutcome{}
	}

	outcome := auditOutcome{
		Enabled:      true,
		WouldAction:  "would_allow",
		WouldReason:  "policy_allowed",
		PolicyBypass: decision != nil && decision.Bypass,
	}
	if decision == nil || !decision.Allowed {
		outcome.WouldAction = "would_deny"
		outcome.WouldBlock = true
		outcome.WouldReason = "policy_denied"
	}
	s.recordAuditDecision(protocol, outcome.WouldAction, reqIdentity, fqdn, decisionPolicyName(decision), outcome.WouldReason)
	return outcome
}

func (s *Server) recordUnknownIdentityAuditDecision(protocol string, reqIdentity *identity.Identity, fqdn string) auditOutcome {
	if !s.auditMode() {
		return auditOutcome{}
	}
	outcome := auditOutcome{
		Enabled:     true,
		WouldAction: "would_deny",
		WouldBlock:  true,
		WouldReason: "unknown_identity",
	}
	s.recordAuditDecision(protocol, outcome.WouldAction, reqIdentity, fqdn, "", outcome.WouldReason)
	return outcome
}

func (s *Server) denyUnknownIdentity(id *identity.Identity) bool {
	return config.NormalizeUnknownIdentityPolicy(s.deps.UnknownIdentityPolicy) == config.UnknownIdentityDeny && isUnknownIdentity(id)
}

func isUnknownIdentity(id *identity.Identity) bool {
	return id == nil || id.Source == "unknown" || id.Name == identity.Unknown().Name
}

func auditActualReason(audit auditOutcome) string {
	if !audit.Enabled {
		return "policy_allowed"
	}
	if audit.WouldBlock {
		if audit.WouldReason == "unknown_identity" {
			return "audit_unknown_identity"
		}
		return "audit_policy_denied"
	}
	return "audit_policy_allowed"
}

func auditLogLevel(audit auditOutcome) slog.Level {
	if audit.Enabled && audit.WouldBlock {
		return slog.LevelWarn
	}
	return slog.LevelInfo
}
