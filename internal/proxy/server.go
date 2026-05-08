package proxy

import (
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
	"net/url"
	"strconv"
	"strings"
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
	ConnectionIdleTimeout time.Duration
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

func NewServer(deps Dependencies) *Server {
	if deps.Logger == nil {
		deps.Logger = slog.Default()
	}
	if deps.ConnectionIdleTimeout <= 0 {
		deps.ConnectionIdleTimeout = 2 * time.Minute
	}
	if deps.UpstreamHTTPTransport == nil {
		deps.UpstreamHTTPTransport = NewUpstreamHTTPTransport()
	}
	server := &Server{deps: deps}
	server.deps.UpstreamHTTPTransport.Proxy = nil
	server.deps.UpstreamHTTPTransport.DialContext = server.dialUpstreamContext
	if server.deps.UpstreamTLSConfig != nil {
		server.deps.UpstreamHTTPTransport.TLSClientConfig = server.deps.UpstreamTLSConfig.Clone()
		if server.deps.UpstreamHTTPTransport.TLSClientConfig.MinVersion == 0 {
			server.deps.UpstreamHTTPTransport.TLSClientConfig.MinVersion = tls.VersionTLS12
		}
	}
	return server
}

func NewUpstreamHTTPTransport() *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSClientConfig = nil
	transport.MaxIdleConns = 1024
	transport.MaxIdleConnsPerHost = 256
	transport.MaxConnsPerHost = 128
	transport.IdleConnTimeout = 90 * time.Second
	transport.ForceAttemptHTTP2 = true
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

func prepareOutboundRequest(req *http.Request) *http.Request {
	outReq := req.Clone(req.Context())
	outReq.RequestURI = ""
	outReq.Close = false
	outReq.URL = cloneRequestURL(req.URL)
	removeHopByHopHeaders(outReq.Header)
	if requestHasReplaySafeEmptyBody(req) {
		outReq.Body = nil
		outReq.GetBody = nil
		outReq.ContentLength = 0
	}
	return outReq
}

func requestHasReplaySafeEmptyBody(req *http.Request) bool {
	if req == nil {
		return false
	}
	if req.ContentLength > 0 {
		return false
	}
	if len(req.TransferEncoding) > 0 {
		return false
	}
	return req.Body == nil || req.Body == http.NoBody || req.ContentLength == 0
}

func (s *Server) dialUpstreamContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, portValue, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if ip := net.ParseIP(host); ip != nil {
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	port, err := strconv.Atoi(portValue)
	if err != nil {
		return nil, err
	}
	targetAddr, err := s.resolveAddr(ctx, host, port)
	if err != nil {
		return nil, err
	}
	return (&net.Dialer{}).DialContext(ctx, network, targetAddr)
}

func (s *Server) wrapIdleConn(conn net.Conn) net.Conn {
	if conn == nil || s.deps.ConnectionIdleTimeout <= 0 {
		return conn
	}
	return &idleDeadlineConn{
		Conn:        conn,
		idleTimeout: s.deps.ConnectionIdleTimeout,
	}
}

func (s *Server) wrapIdleReader(conn net.Conn, reader io.Reader) io.Reader {
	if reader == nil || conn == nil || s.deps.ConnectionIdleTimeout <= 0 {
		return reader
	}
	return &idleDeadlineReader{
		conn:        conn,
		reader:      reader,
		idleTimeout: s.deps.ConnectionIdleTimeout,
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

func cloneRequestURL(in *url.URL) *url.URL {
	if in == nil {
		return &url.URL{}
	}
	cloned := *in
	return &cloned
}

func copyHeader(dst, src http.Header) {
	for key, values := range src {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func declareTrailers(header http.Header, trailers http.Header) {
	for key := range trailers {
		header.Add("Trailer", key)
	}
}

func copyTrailers(dst, src http.Header) {
	for key, values := range src {
		if trailerDeclared(dst, key) {
			dst.Del(key)
			for _, value := range values {
				dst.Add(key, value)
			}
			continue
		}
		prefixedKey := http.TrailerPrefix + key
		dst.Del(prefixedKey)
		for _, value := range values {
			dst.Add(prefixedKey, value)
		}
	}
}

func trailerDeclared(header http.Header, key string) bool {
	for _, value := range header.Values("Trailer") {
		for _, token := range connectionHeaderTokens([]string{value}) {
			if token == textproto.CanonicalMIMEHeaderKey(key) {
				return true
			}
		}
	}
	return false
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

type idleDeadlineConn struct {
	net.Conn
	idleTimeout time.Duration
}

func (c *idleDeadlineConn) Read(p []byte) (int, error) {
	if err := c.Conn.SetReadDeadline(time.Now().Add(c.idleTimeout)); err != nil {
		return 0, err
	}
	return c.Conn.Read(p)
}

func (c *idleDeadlineConn) Write(p []byte) (int, error) {
	if err := c.Conn.SetWriteDeadline(time.Now().Add(c.idleTimeout)); err != nil {
		return 0, err
	}
	return c.Conn.Write(p)
}

type idleDeadlineReader struct {
	conn        net.Conn
	reader      io.Reader
	idleTimeout time.Duration
}

func (r *idleDeadlineReader) Read(p []byte) (int, error) {
	if err := r.conn.SetReadDeadline(time.Now().Add(r.idleTimeout)); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

func connectDecisionMode(outcome policy.Outcome) string {
	if outcome.RequestedTLSMode == "" {
		return "unknown"
	}
	return outcome.RequestedTLSMode
}

func connectResolvedMode(outcome policy.Outcome) string {
	if outcome.EffectiveTLSMode == "" {
		return "passthrough"
	}
	return outcome.EffectiveTLSMode
}
