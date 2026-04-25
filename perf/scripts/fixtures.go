package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"time"
)

type fixtureConfig struct {
	Mode   string
	Listen string
	Path   string
}

type runningFixture struct {
	addr     string
	shutdown func(context.Context) error
	errCh    <-chan error
}

func parseFixtureConfig(args []string) (fixtureConfig, error) {
	fs := flag.NewFlagSet("fixtures", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	cfg := fixtureConfig{}
	fs.StringVar(&cfg.Mode, "mode", "http", "http|passthrough|mitm")
	fs.StringVar(&cfg.Listen, "listen", "127.0.0.1:0", "listen address")
	fs.StringVar(&cfg.Path, "path", "/allowed", "allowed path")
	if err := fs.Parse(args); err != nil {
		return fixtureConfig{}, err
	}
	switch cfg.Mode {
	case "http", "passthrough", "mitm":
	default:
		return fixtureConfig{}, fmt.Errorf("invalid mode %q", cfg.Mode)
	}

	return cfg, nil
}

func newHTTPFixture(path string, successStatus int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != path {
			http.NotFound(w, r)
			return
		}

		w.WriteHeader(successStatus)
	})
}

func startFixture(cfg fixtureConfig, stdout io.Writer) (*runningFixture, error) {
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return nil, err
	}

	srv := &http.Server{
		Handler: newHTTPFixture(cfg.Path, http.StatusNoContent),
	}

	if _, err := fmt.Fprintf(stdout, "LISTEN_ADDR=%s\n", ln.Addr().String()); err != nil {
		_ = ln.Close()
		return nil, err
	}

	serveFn := func() error {
		return srv.Serve(ln)
	}
	if cfg.Mode == "passthrough" || cfg.Mode == "mitm" {
		tlsConfig, err := newFixtureTLSConfig()
		if err != nil {
			_ = ln.Close()
			return nil, err
		}
		tlsListener := tls.NewListener(ln, tlsConfig)
		serveFn = func() error {
			return srv.Serve(tlsListener)
		}
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- serveFn()
	}()

	return &runningFixture{
		addr:     ln.Addr().String(),
		shutdown: srv.Shutdown,
		errCh:    errCh,
	}, nil
}

func runFixture(args []string, stdout io.Writer) error {
	cfg, err := parseFixtureConfig(args)
	if err != nil {
		return err
	}

	fixture, err := startFixture(cfg, stdout)
	if err != nil {
		return err
	}

	err = <-fixture.errCh
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func newFixtureTLSConfig() (*tls.Config, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, err
	}

	certificateTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "aegis-perf-fixture",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	certificateDER, err := x509.CreateCertificate(rand.Reader, certificateTemplate, certificateTemplate, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}

	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	certificate, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS12,
	}, nil
}

func main() {
	if err := runFixture(os.Args[1:], os.Stdout); err != nil {
		log.Fatal(err)
	}
}
