package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/moolen/aegis/internal/identity"
)

func (s *Server) handleConnectMITM(clientConn net.Conn, clientReader *bufio.Reader, clientHello []byte, reqIdentity *identity.Identity, sourceIP netip.Addr, serverName string, port int) {
	clientTLSConn, err := s.handshakeClientMITM(clientConn, clientReader, clientHello, serverName)
	if err != nil {
		s.observeMITMClientHandshakeError(serverName, err)
		clientConn.Close()
		return
	}
	defer clientTLSConn.Close()

	s.observeMITMEstablished()
	srv := newMITMHTTPServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		s.handleMITMHTTPRequest(w, req, reqIdentity, sourceIP, serverName, port)
	}))
	srv.IdleTimeout = s.deps.ConnectionIdleTimeout
	var serveDone sync.Once
	serveDoneCh := make(chan struct{})
	srv.ConnState = func(conn net.Conn, state http.ConnState) {
		if conn == clientTLSConn && state == http.StateClosed {
			serveDone.Do(func() {
				close(serveDoneCh)
			})
		}
	}
	if err := srv.Serve(&singleUseListener{
		addr: clientTLSConn.LocalAddr(),
		conn: clientTLSConn,
		done: serveDoneCh,
	}); err != nil && !isConnectionClosed(err) {
		s.observeMITMServeError(serverName, err)
	}
}

func (s *Server) forwardMITMRequest(w http.ResponseWriter, req *http.Request, flow *requestFlow) {
	resp, err := s.roundTripMITMRequest(req, flow.host, flow.port)
	if err != nil {
		s.observeMITMUpstreamError(flow, err)
		http.Error(w, "upstream response failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	removeHopByHopHeaders(resp.Header)
	copyHeader(w.Header(), resp.Header)
	declareTrailers(w.Header(), resp.Trailer)
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil && !isConnectionClosed(err) {
		s.observeMITMWriteClientError(flow, err)
	}
	copyTrailers(w.Header(), resp.Trailer)
}

func (s *Server) roundTripMITMRequest(req *http.Request, serverName string, port int) (*http.Response, error) {
	outReq := prepareOutboundRequest(req)
	outReq.URL.Scheme = "https"
	outReq.URL.Host = net.JoinHostPort(serverName, strconv.Itoa(port))
	if outReq.Host == "" {
		outReq.Host = serverName
	}

	return s.deps.UpstreamHTTPTransport.RoundTrip(outReq)
}

func (s *Server) handshakeClientMITM(clientConn net.Conn, clientReader *bufio.Reader, clientHello []byte, serverName string) (*tls.Conn, error) {
	certificate, result, err := s.deps.MITM.CertificateForSNI(serverName)
	if err != nil {
		s.observeMITMCertificateResult("error")
		return nil, err
	}
	s.observeMITMCertificateResult(result)

	wrappedClientConn := s.wrapIdleConn(clientConn)
	tlsConn := tls.Server(&replayConn{
		Conn:   wrappedClientConn,
		reader: io.MultiReader(bytes.NewReader(clientHello), s.wrapIdleReader(wrappedClientConn, clientReader)),
	}, &tls.Config{
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1"},
		Certificates: []tls.Certificate{*certificate},
	})
	if err := tlsConn.Handshake(); err != nil {
		return nil, err
	}

	return tlsConn, nil
}

type singleUseListener struct {
	addr net.Addr
	conn net.Conn
	done chan struct{}
	once sync.Once
}

func (l *singleUseListener) Accept() (net.Conn, error) {
	var conn net.Conn
	l.once.Do(func() {
		conn = l.conn
		l.conn = nil
	})
	if conn != nil {
		return conn, nil
	}
	<-l.done
	return nil, net.ErrClosed
}

func (l *singleUseListener) Close() error {
	return nil
}

func (l *singleUseListener) Addr() net.Addr {
	return l.addr
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
		s.observeUpstreamTLSHandshakeError()
		upstreamConn.Close()
		return nil, err
	}

	return tlsConn, nil
}

func isUpstreamTLSHandshakeError(err error) bool {
	var urlErr *url.Error
	if errors.As(err, &urlErr) && urlErr.Err != nil {
		err = urlErr.Err
	}

	var (
		certVerificationErr *tls.CertificateVerificationError
		certInvalidErr      x509.CertificateInvalidError
		unknownAuthorityErr x509.UnknownAuthorityError
		hostnameErr         x509.HostnameError
		recordHeaderErr     tls.RecordHeaderError
	)
	switch {
	case errors.As(err, &certVerificationErr):
		return true
	case errors.As(err, &certInvalidErr):
		return true
	case errors.As(err, &unknownAuthorityErr):
		return true
	case errors.As(err, &hostnameErr):
		return true
	case errors.As(err, &recordHeaderErr):
		return true
	}

	message := err.Error()
	return strings.Contains(message, "tls:") || strings.Contains(message, "x509:")
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
