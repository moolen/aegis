package metrics

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
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

type AdminAPI interface {
	AdminToken() string
	EnforcementStatus() EnforcementStatus
	RuntimeStatus() RuntimeStatus
	SetEnforcementMode(mode string) (EnforcementStatus, error)
	Reload() error
	DumpIdentities() []IdentityDumpRecord
	Simulate(SimulationRequest) (SimulationResponse, error)
}

type EnforcementStatus struct {
	Configured string `json:"configured"`
	Override   string `json:"override,omitempty"`
	Effective  string `json:"effective"`
}

type RuntimeStatus struct {
	MITM *MITMStatus `json:"mitm,omitempty"`
}

type MITMStatus struct {
	Enabled               bool     `json:"enabled"`
	IssuerFingerprint     string   `json:"issuerFingerprint,omitempty"`
	CompanionFingerprints []string `json:"companionFingerprints,omitempty"`
	AllFingerprints       []string `json:"allFingerprints,omitempty"`
}

type IdentityRecord struct {
	Source   string            `json:"source"`
	Provider string            `json:"provider,omitempty"`
	Kind     string            `json:"kind,omitempty"`
	Name     string            `json:"name"`
	Labels   map[string]string `json:"labels,omitempty"`
}

type IdentityDumpRecord struct {
	IP        string           `json:"ip"`
	Effective *IdentityRecord  `json:"effective,omitempty"`
	Shadows   []IdentityRecord `json:"shadows,omitempty"`
}

type SimulationRequest struct {
	SourceIP string `json:"sourceIP"`
	FQDN     string `json:"fqdn"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Method   string `json:"method,omitempty"`
	Path     string `json:"path,omitempty"`
}

type SimulationDecision struct {
	Allowed           bool   `json:"allowed"`
	Policy            string `json:"policy,omitempty"`
	Rule              string `json:"rule,omitempty"`
	TLSMode           string `json:"tlsMode,omitempty"`
	Bypass            bool   `json:"bypass,omitempty"`
	PolicyEnforcement string `json:"policyEnforcement,omitempty"`
}

type SimulationResponse struct {
	Identity              *IdentityRecord     `json:"identity,omitempty"`
	UnknownIdentity       bool                `json:"unknownIdentity"`
	UnknownIdentityPolicy string              `json:"unknownIdentityPolicy"`
	ConfiguredMode        string              `json:"configuredMode"`
	OverrideMode          string              `json:"overrideMode,omitempty"`
	EffectiveMode         string              `json:"effectiveMode"`
	Protocol              string              `json:"protocol"`
	FQDN                  string              `json:"fqdn"`
	Port                  int                 `json:"port"`
	Method                string              `json:"method,omitempty"`
	Path                  string              `json:"path,omitempty"`
	Action                string              `json:"action"`
	Reason                string              `json:"reason"`
	WouldAction           string              `json:"wouldAction,omitempty"`
	WouldReason           string              `json:"wouldReason,omitempty"`
	WouldBlock            bool                `json:"wouldBlock,omitempty"`
	Decision              *SimulationDecision `json:"decision,omitempty"`
}

func NewServer(addr string, reg *prometheus.Registry, readyChecker ReadyChecker, adminAPI AdminAPI) *Server {
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
	return &Server{
		addr:    addr,
		handler: mux,
	}
}

func NewAdminServer(addr string, adminAPI AdminAPI) *Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/enforcement", func(w http.ResponseWriter, r *http.Request) {
		if adminAPI == nil || strings.TrimSpace(adminAPI.AdminToken()) == "" {
			http.NotFound(w, r)
			return
		}
		if !authorizeAdminRequest(r, adminAPI.AdminToken()) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="aegis-admin"`)
			http.Error(w, "admin authorization required", http.StatusUnauthorized)
			return
		}

		switch r.Method {
		case http.MethodGet:
			writeJSON(w, adminAPI.EnforcementStatus())
		case http.MethodPost:
			status, err := adminAPI.SetEnforcementMode(r.URL.Query().Get("mode"))
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			writeJSON(w, status)
		default:
			w.Header().Set("Allow", "GET, POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/admin/identities", func(w http.ResponseWriter, r *http.Request) {
		if !authorizeAdminEndpoint(w, r, adminAPI) {
			return
		}
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writeJSON(w, adminAPI.DumpIdentities())
	})
	mux.HandleFunc("/admin/runtime", func(w http.ResponseWriter, r *http.Request) {
		if !authorizeAdminEndpoint(w, r, adminAPI) {
			return
		}
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writeJSON(w, adminAPI.RuntimeStatus())
	})
	mux.HandleFunc("/admin/reload", func(w http.ResponseWriter, r *http.Request) {
		if !authorizeAdminEndpoint(w, r, adminAPI) {
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := adminAPI.Reload(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/admin/simulate", func(w http.ResponseWriter, r *http.Request) {
		if !authorizeAdminEndpoint(w, r, adminAPI) {
			return
		}
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		req, err := simulationRequestFromQuery(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		resp, err := adminAPI.Simulate(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, resp)
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

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func authorizeAdminEndpoint(w http.ResponseWriter, r *http.Request, adminAPI AdminAPI) bool {
	if adminAPI == nil || strings.TrimSpace(adminAPI.AdminToken()) == "" {
		http.NotFound(w, r)
		return false
	}
	if !authorizeAdminRequest(r, adminAPI.AdminToken()) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="aegis-admin"`)
		http.Error(w, "admin authorization required", http.StatusUnauthorized)
		return false
	}
	return true
}

func simulationRequestFromQuery(r *http.Request) (SimulationRequest, error) {
	query := r.URL.Query()
	sourceIP := strings.TrimSpace(query.Get("sourceIP"))
	if sourceIP == "" {
		return SimulationRequest{}, fmt.Errorf("sourceIP is required")
	}
	if net.ParseIP(sourceIP) == nil {
		return SimulationRequest{}, fmt.Errorf("sourceIP must be a valid IP address")
	}
	fqdn := strings.TrimSpace(query.Get("fqdn"))
	if fqdn == "" {
		return SimulationRequest{}, fmt.Errorf("fqdn is required")
	}
	port, err := strconv.Atoi(query.Get("port"))
	if err != nil || port < 1 || port > 65535 {
		return SimulationRequest{}, fmt.Errorf("port must be between 1 and 65535")
	}
	protocol := strings.ToLower(strings.TrimSpace(query.Get("protocol")))
	if protocol == "" {
		protocol = "http"
	}
	switch protocol {
	case "http", "connect":
	default:
		return SimulationRequest{}, fmt.Errorf("protocol must be http or connect")
	}

	return SimulationRequest{
		SourceIP: sourceIP,
		FQDN:     fqdn,
		Port:     port,
		Protocol: protocol,
		Method:   query.Get("method"),
		Path:     query.Get("path"),
	}, nil
}
