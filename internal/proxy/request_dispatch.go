package proxy

import (
	"net/http"
	"net/netip"

	"github.com/moolen/aegis/internal/identity"
)

func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	flow, err := s.evaluateRequestFlow(requestFlowInput{
		Protocol: "http",
		Request:  r,
	})
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error(), "request")
		return
	}
	defer flow.release()

	if s.respondFlowDenial(w, r, flow, "") {
		return
	}

	s.observeAllowedRequestFlow(r, flow)
	s.forwardHTTP(w, r, flow)
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	flow, err := s.evaluateRequestFlow(requestFlowInput{
		Protocol: "connect",
		Request:  r,
	})
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error(), "request")
		return
	}
	defer flow.release()

	if s.respondFlowDenial(w, nil, flow, "") {
		return
	}

	s.observeAllowedRequestFlow(nil, flow)
	s.forwardConnect(w, r, flow)
}

func (s *Server) handleMITMHTTPRequest(w http.ResponseWriter, req *http.Request, reqIdentity *identity.Identity, sourceIP netip.Addr, serverName string, port int) {
	flow, err := s.evaluateRequestFlow(requestFlowInput{
		Protocol: "mitm_http",
		Request:  req,
		Target: &requestFlowTarget{
			Host: serverName,
			Port: port,
		},
		Identity: reqIdentity,
		SourceIP: sourceIP,
	})
	if err != nil {
		s.observeMITMFlowEvaluationError(serverName, err)
		http.Error(w, "internal proxy error", http.StatusInternalServerError)
		return
	}
	defer flow.release()

	if s.respondFlowDenial(w, req, flow, serverName) {
		return
	}

	s.observeAllowedRequestFlow(req, flow)
	s.forwardMITMRequest(w, req, flow)
}
