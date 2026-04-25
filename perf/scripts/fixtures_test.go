package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

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

func startTestFixture(t *testing.T, cfg fixtureConfig) (*runningFixture, func()) {
	t.Helper()

	var stdout bytes.Buffer
	fixture, err := startFixture(cfg, &stdout)
	if err != nil {
		t.Fatalf("startFixture() error = %v", err)
	}

	stop := func() {
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

	return fixture, stop
}
