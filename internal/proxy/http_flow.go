package proxy

import (
	"io"
	"net/http"
)

func (s *Server) forwardHTTP(w http.ResponseWriter, r *http.Request, flow *requestFlow) {
	targetAddr, err := s.resolveAddr(r.Context(), flow.host, flow.port)
	if err != nil {
		if IsDestinationBlocked(err) {
			s.observeHTTPDestinationBlocked(r, flow, err)
			s.writeError(w, http.StatusForbidden, "destination blocked by proxy", "destination")
			return
		}
		s.observeHTTPDNSError(flow, err)
		s.writeError(w, http.StatusBadGateway, "upstream name resolution failed", "dns")
		return
	}

	outReq := prepareOutboundRequest(r)
	outReq.Host = r.Host
	outReq.URL.Host = targetAddr

	resp, err := s.deps.UpstreamHTTPTransport.RoundTrip(outReq)
	if err != nil {
		s.observeHTTPDialError(flow, targetAddr, err)
		s.writeError(w, http.StatusBadGateway, "upstream connection failed", "dial")
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
