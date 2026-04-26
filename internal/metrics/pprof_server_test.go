package metrics

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewPprofServerExposesIndex(t *testing.T) {
	srv := NewPprofServer("127.0.0.1:0")
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/debug/pprof/")
	if err != nil {
		t.Fatalf("GET /debug/pprof/ error = %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if !strings.Contains(string(body), "heap?debug=1") {
		t.Fatalf("body did not include heap profile link")
	}
}

func TestNewPprofServerExposesHeapProfile(t *testing.T) {
	srv := NewPprofServer("127.0.0.1:0")
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/debug/pprof/heap?debug=1")
	if err != nil {
		t.Fatalf("GET /debug/pprof/heap error = %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if !strings.Contains(string(body), "heap profile") {
		t.Fatalf("body did not include heap profile output")
	}
}
