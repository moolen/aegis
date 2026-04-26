package proxy

import (
	"crypto/tls"
	"net/http"
	"time"

	"golang.org/x/net/http2"
)

func newMITMHTTPServer(handler http.Handler) *http.Server {
	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			NextProtos: []string{"h2", "http/1.1"},
		},
	}
	_ = http2.ConfigureServer(srv, &http2.Server{})
	return srv
}
