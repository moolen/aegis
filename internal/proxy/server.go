package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

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
	Evaluate(id *identity.Identity, fqdn string, port int, method string, path string) *policy.Decision
	EvaluateConnect(id *identity.Identity, fqdn string, port int) *policy.Decision
}

type Dependencies struct {
	Resolver         Resolver
	IdentityResolver IdentityResolver
	PolicyEngine     PolicyEngine
	Metrics          *metrics.Metrics
	Logger           *slog.Logger
}

type Server struct {
	deps Dependencies
}

func NewServer(deps Dependencies) *Server {
	if deps.Logger == nil {
		deps.Logger = slog.Default()
	}
	return &Server{deps: deps}
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

	if s.deps.PolicyEngine != nil {
		reqIdentity := s.resolveRequestIdentity(r)
		decision := s.deps.PolicyEngine.Evaluate(reqIdentity, host, port, r.Method, requestPolicyPath(r))
		if decision == nil || !decision.Allowed {
			s.writeError(w, http.StatusForbidden, "request denied by policy", "policy")
			return
		}
	}

	targetAddr, err := s.resolveAddr(r.Context(), host, port)
	if err != nil {
		s.writeError(w, http.StatusBadGateway, err.Error(), "dns")
		return
	}

	outReq := r.Clone(r.Context())
	outReq.RequestURI = ""
	outReq.Host = r.Host
	removeHopByHopHeaders(outReq.Header)

	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			dialer := &net.Dialer{}
			return dialer.DialContext(ctx, network, targetAddr)
		},
	}
	defer transport.CloseIdleConnections()

	resp, err := transport.RoundTrip(outReq)
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

	if s.deps.PolicyEngine != nil {
		reqIdentity := s.resolveRequestIdentity(r)
		decision := s.deps.PolicyEngine.EvaluateConnect(reqIdentity, host, port)
		if decision == nil || !decision.Allowed {
			s.writeError(w, http.StatusForbidden, "connect target denied by policy", "policy")
			return
		}
		if decision.TLSMode == "mitm" {
			s.writeError(w, http.StatusNotImplemented, "connect tls mitm not implemented", "tls")
			return
		}
	}

	targetAddr, err := s.resolveAddr(r.Context(), host, port)
	if err != nil {
		s.writeError(w, http.StatusBadGateway, err.Error(), "dns")
		return
	}

	upstreamConn, err := (&net.Dialer{}).DialContext(r.Context(), "tcp", targetAddr)
	if err != nil {
		s.writeError(w, http.StatusBadGateway, fmt.Sprintf("connect upstream failed: %v", err), "dial")
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		upstreamConn.Close()
		s.writeError(w, http.StatusInternalServerError, "response writer does not support hijacking", "server")
		return
	}

	clientConn, buf, err := hijacker.Hijack()
	if err != nil {
		upstreamConn.Close()
		s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("hijack failed: %v", err), "server")
		return
	}

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		clientConn.Close()
		upstreamConn.Close()
		return
	}

	if err := clientConn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		s.deps.Logger.Debug("set connect client read deadline failed", "error", err)
	}
	clientHello, sni, err := readClientHello(buf.Reader)
	_ = clientConn.SetReadDeadline(time.Time{})
	if err != nil {
		s.recordTLSConnectBlock(err)
		s.deps.Logger.Warn("connect tls inspection failed", "target", host, "error", err)
		clientConn.Close()
		upstreamConn.Close()
		return
	}
	if !strings.EqualFold(sni, host) {
		s.recordTLSConnectBlock(nil)
		s.deps.Logger.Warn("connect tls sni mismatch", "target", host, "sni", sni)
		clientConn.Close()
		upstreamConn.Close()
		return
	}
	if _, err := upstreamConn.Write(clientHello); err != nil {
		clientConn.Close()
		upstreamConn.Close()
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, _ = io.Copy(upstreamConn, buf.Reader)
		_ = upstreamConn.Close()
	}()

	go func() {
		defer wg.Done()
		_, _ = io.Copy(clientConn, upstreamConn)
		_ = clientConn.Close()
	}()

	wg.Wait()
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

	remoteHost, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		s.deps.Logger.Debug("split remote address failed", "remote_addr", r.RemoteAddr, "error", err)
		return reqIdentity
	}

	remoteIP := net.ParseIP(remoteHost)
	if remoteIP == nil {
		s.deps.Logger.Debug("parse remote ip failed", "remote_addr", r.RemoteAddr)
		return reqIdentity
	}

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

	return net.JoinHostPort(ips[0].String(), strconv.Itoa(port)), nil
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
