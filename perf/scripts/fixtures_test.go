package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
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
