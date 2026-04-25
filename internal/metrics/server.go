package metrics

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Server struct {
	addr    string
	handler http.Handler
}

type ReadyChecker interface {
	CheckReadiness() error
}

type EnforcementAdmin interface {
	AdminToken() string
	EnforcementStatus() EnforcementStatus
	SetEnforcementMode(mode string) (EnforcementStatus, error)
}

type EnforcementStatus struct {
	Configured string `json:"configured"`
	Override   string `json:"override,omitempty"`
	Effective  string `json:"effective"`
}

func NewServer(addr string, reg *prometheus.Registry, readyChecker ReadyChecker, enforcementAdmin EnforcementAdmin) *Server {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if readyChecker != nil {
			if err := readyChecker.CheckReadiness(); err != nil {
				http.Error(w, err.Error(), http.StatusServiceUnavailable)
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/admin/enforcement", func(w http.ResponseWriter, r *http.Request) {
		if enforcementAdmin == nil || strings.TrimSpace(enforcementAdmin.AdminToken()) == "" {
			http.NotFound(w, r)
			return
		}
		if !authorizeAdminRequest(r, enforcementAdmin.AdminToken()) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="aegis-admin"`)
			http.Error(w, "admin authorization required", http.StatusUnauthorized)
			return
		}

		switch r.Method {
		case http.MethodGet:
			writeEnforcementStatus(w, enforcementAdmin.EnforcementStatus())
		case http.MethodPost:
			status, err := enforcementAdmin.SetEnforcementMode(r.URL.Query().Get("mode"))
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			writeEnforcementStatus(w, status)
		default:
			w.Header().Set("Allow", "GET, POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	return &Server{
		addr:    addr,
		handler: mux,
	}
}

func (s *Server) Addr() string {
	return s.addr
}

func (s *Server) Handler() http.Handler {
	return s.handler
}

func authorizeAdminRequest(r *http.Request, token string) bool {
	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	if authHeader == "" {
		return false
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(authHeader, prefix) {
		return false
	}
	return strings.TrimSpace(strings.TrimPrefix(authHeader, prefix)) == token
}

func writeEnforcementStatus(w http.ResponseWriter, status EnforcementStatus) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(status)
}
