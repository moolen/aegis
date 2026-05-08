package proxy

import (
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

func (s *Server) forwardConnect(w http.ResponseWriter, r *http.Request, flow *requestFlow) {
	targetAddr, err := s.resolveAddr(r.Context(), flow.host, flow.port)
	if err != nil {
		if IsDestinationBlocked(err) {
			s.observeConnectDestinationBlocked(flow, err)
			s.writeError(w, http.StatusForbidden, "destination blocked by proxy", "destination")
			return
		}
		s.observeConnectDNSError(flow, err)
		s.writeError(w, http.StatusBadGateway, "upstream name resolution failed", "dns")
		return
	}

	var upstreamConn net.Conn
	if flow.mode != "mitm" {
		upstreamConn, err = (&net.Dialer{}).DialContext(r.Context(), "tcp", targetAddr)
		if err != nil {
			s.observeConnectDialError(flow, targetAddr, err)
			s.writeError(w, http.StatusBadGateway, "upstream connection failed", "dial")
			return
		}
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		if upstreamConn != nil {
			upstreamConn.Close()
		}
		s.observeConnectServerError(flow.mode, "connect response writer does not support hijacking", nil)
		s.writeError(w, http.StatusInternalServerError, "internal proxy error", "server")
		return
	}

	clientConn, buf, err := hijacker.Hijack()
	if err != nil {
		if upstreamConn != nil {
			upstreamConn.Close()
		}
		s.observeConnectServerError(flow.mode, "connect hijack failed", err)
		s.writeError(w, http.StatusInternalServerError, "internal proxy error", "server")
		return
	}

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		clientConn.Close()
		if upstreamConn != nil {
			upstreamConn.Close()
		}
		return
	}
	releaseTunnel := s.trackConnectTunnel(flow.mode, clientConn, upstreamConn)
	defer releaseTunnel()

	if flow.audit.Enabled {
		s.observeConnectEstablished(flow)
		s.spliceConnectTunnel(s.wrapIdleConn(clientConn), s.wrapIdleConn(upstreamConn), s.wrapIdleReader(clientConn, buf.Reader))
		return
	}

	if err := clientConn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		s.deps.Logger.Debug("set connect client read deadline failed", "error", err)
	}
	clientHello, sni, err := readClientHello(buf.Reader)
	_ = clientConn.SetReadDeadline(time.Time{})
	if err != nil {
		s.observeConnectTLSInspectionError(flow, err)
		clientConn.Close()
		if upstreamConn != nil {
			upstreamConn.Close()
		}
		return
	}
	if !strings.EqualFold(sni, flow.host) {
		s.observeConnectTLSMismatch(flow, sni)
		clientConn.Close()
		if upstreamConn != nil {
			upstreamConn.Close()
		}
		return
	}

	if flow.mode == "mitm" {
		s.handleConnectMITM(clientConn, buf.Reader, clientHello, flow.identity, flow.sourceIP, sni, flow.port)
		return
	}

	if _, err := upstreamConn.Write(clientHello); err != nil {
		s.observeConnectTLSForwardError(flow)
		clientConn.Close()
		upstreamConn.Close()
		return
	}

	s.observeConnectEstablished(flow)
	s.spliceConnectTunnel(s.wrapIdleConn(clientConn), s.wrapIdleConn(upstreamConn), s.wrapIdleReader(clientConn, buf.Reader))
}

func (s *Server) trackConnectTunnel(mode string, closers ...io.Closer) func() {
	if s.deps.DrainTracker == nil {
		return func() {}
	}
	return s.deps.DrainTracker.Track(mode, closers...)
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
