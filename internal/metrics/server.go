package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Server struct {
	addr    string
	handler http.Handler
}

func NewServer(addr string, reg *prometheus.Registry) *Server {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
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
