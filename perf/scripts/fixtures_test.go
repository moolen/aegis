package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestLocalPerfConfigTemplatesExist(t *testing.T) {
	paths := []string{
		"../config/local-http.yaml",
		"../config/local-connect-passthrough.yaml",
		"../config/local-connect-mitm.yaml",
		"../k6/http.js",
		"../k6/connect_passthrough.js",
		"../k6/connect_mitm.js",
	}

	for _, path := range paths {
		path := path
		t.Run(path, func(t *testing.T) {
			t.Parallel()

			if _, err := os.Stat(path); err != nil {
				t.Fatalf("os.Stat(%q) error = %v", path, err)
			}
		})
	}
}

func TestHTTPFixtureServesConfiguredPath(t *testing.T) {
	srv := newHTTPFixture("/allowed", http.StatusNoContent)
	req := httptest.NewRequest(http.MethodGet, "http://fixture/allowed", nil)
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
}

func TestHTTPFixtureRejectsUnexpectedPath(t *testing.T) {
	srv := newHTTPFixture("/allowed", http.StatusNoContent)
	req := httptest.NewRequest(http.MethodGet, "http://fixture/denied", nil)
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestFixtureConfigParsesTLSMode(t *testing.T) {
	cfg, err := parseFixtureConfig([]string{"-mode", "mitm", "-listen", "127.0.0.1:0", "-path", "/allowed"})
	if err != nil {
		t.Fatalf("parseFixtureConfig() error = %v", err)
	}
	if cfg.Mode != "mitm" {
		t.Fatalf("mode = %q, want %q", cfg.Mode, "mitm")
	}
}

func TestFixtureConfigRejectsInvalidMode(t *testing.T) {
	_, err := parseFixtureConfig([]string{"-mode", "bogus"})
	if err == nil {
		t.Fatal("parseFixtureConfig() error = nil, want non-nil")
	}
}

func TestHTTPModeServesPlainHTTP(t *testing.T) {
	fixture, stop := startTestFixture(t, fixtureConfig{
		Mode:   "http",
		Listen: "127.0.0.1:0",
		Path:   "/allowed",
	})
	defer stop()

	client := &http.Client{Timeout: time.Second}
	resp, err := client.Get("http://" + fixture.addr + "/allowed")
	if err != nil {
		t.Fatalf("HTTP GET in http mode error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}
}

func TestTLSModesServeHTTPS(t *testing.T) {
	for _, mode := range []string{"passthrough", "mitm"} {
		t.Run(mode, func(t *testing.T) {
			fixture, stop := startTestFixture(t, fixtureConfig{
				Mode:   mode,
				Listen: "127.0.0.1:0",
				Path:   "/allowed",
			})
			defer stop()

			httpClient := &http.Client{Timeout: time.Second}
			resp, err := httpClient.Get("http://" + fixture.addr + "/allowed")
			if err == nil {
				defer resp.Body.Close()
				if resp.StatusCode == http.StatusNoContent {
					t.Fatalf("plain HTTP GET unexpectedly returned %d in %s mode", resp.StatusCode, mode)
				}
			}

			httpsClient := &http.Client{
				Timeout: time.Second,
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{RootCAs: fixture.rootCAs},
				},
			}
			resp, err = httpsClient.Get("https://" + fixture.addr + "/allowed")
			if err != nil {
				t.Fatalf("HTTPS GET in %s mode error = %v", mode, err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusNoContent {
				t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
			}
		})
	}
}

func TestTLSModesPublishVerifiableAddress(t *testing.T) {
	for _, mode := range []string{"passthrough", "mitm"} {
		t.Run(mode, func(t *testing.T) {
			fixture, stop := startTestFixture(t, fixtureConfig{
				Mode:   mode,
				Listen: "0.0.0.0:0",
				Path:   "/allowed",
			})
			defer stop()

			client := &http.Client{
				Timeout: time.Second,
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{RootCAs: fixture.rootCAs},
				},
			}
			resp, err := client.Get("https://" + fixture.addr + "/allowed")
			if err != nil {
				t.Fatalf("HTTPS GET via published address error = %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusNoContent {
				t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
			}
		})
	}
}

func TestTLSModesEmitTrustMaterial(t *testing.T) {
	for _, mode := range []string{"passthrough", "mitm"} {
		t.Run(mode, func(t *testing.T) {
			var stdout bytes.Buffer
			fixture, err := startFixture(fixtureConfig{
				Mode:   mode,
				Listen: "127.0.0.1:0",
				Path:   "/allowed",
			}, &stdout)
			if err != nil {
				t.Fatalf("startFixture() error = %v", err)
			}
			defer stopFixture(t, fixture)

			rootCAPEM := stdoutEnvValue(t, stdout.String(), "ROOT_CA_PEM_B64")
			decodedPEM, err := base64.StdEncoding.DecodeString(rootCAPEM)
			if err != nil {
				t.Fatalf("DecodeString(ROOT_CA_PEM_B64) error = %v", err)
			}

			certPool := x509.NewCertPool()
			if ok := certPool.AppendCertsFromPEM(decodedPEM); !ok {
				t.Fatal("AppendCertsFromPEM(ROOT_CA_PEM_B64) = false, want true")
			}

			client := &http.Client{
				Timeout: time.Second,
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{RootCAs: certPool},
				},
			}
			resp, err := client.Get("https://" + fixture.addr + "/allowed")
			if err != nil {
				t.Fatalf("HTTPS GET using emitted trust material error = %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusNoContent {
				t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
			}
		})
	}
}

func TestPublishableFixtureAddrPreservesLoopbackFamily(t *testing.T) {
	if got := publishableFixtureAddr(&net.TCPAddr{IP: net.ParseIP("0.0.0.0"), Port: 3128}); got != "127.0.0.1:3128" {
		t.Fatalf("publishableFixtureAddr(v4 unspecified) = %q, want %q", got, "127.0.0.1:3128")
	}
	if got := publishableFixtureAddr(&net.TCPAddr{IP: net.ParseIP("::"), Port: 3128}); got != "[::1]:3128" {
		t.Fatalf("publishableFixtureAddr(v6 unspecified) = %q, want %q", got, "[::1]:3128")
	}
}

func startTestFixture(t *testing.T, cfg fixtureConfig) (*runningFixture, func()) {
	t.Helper()

	var stdout bytes.Buffer
	fixture, err := startFixture(cfg, &stdout)
	if err != nil {
		t.Fatalf("startFixture() error = %v", err)
	}

	stop := func() {
		t.Helper()
		stopFixture(t, fixture)
	}

	return fixture, stop
}

func stopFixture(t *testing.T, fixture *runningFixture) {
	t.Helper()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := fixture.shutdown(shutdownCtx); err != nil {
		t.Fatalf("fixture.shutdown() error = %v", err)
	}

	select {
	case err := <-fixture.errCh:
		if !errors.Is(err, http.ErrServerClosed) && err != nil {
			t.Fatalf("fixture serve error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for fixture shutdown")
	}
}

func stdoutEnvValue(t *testing.T, stdout string, key string) string {
	t.Helper()

	prefix := key + "="
	for _, line := range strings.Split(stdout, "\n") {
		if strings.HasPrefix(line, prefix) {
			return strings.TrimPrefix(line, prefix)
		}
	}

	t.Fatalf("stdout missing %s in %q", key, stdout)
	return ""
}
