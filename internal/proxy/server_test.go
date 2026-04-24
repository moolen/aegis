package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/moolen/aegis/internal/metrics"
)

func TestProxyForwardsHTTPRequests(t *testing.T) {
	var receivedHost string

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHost = r.Host
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	proxyServer := httptest.NewServer(NewServer(Dependencies{
		Resolver: staticResolver{
			lookup: map[string][]net.IP{
				"service.internal": {net.ParseIP("127.0.0.1")},
			},
		},
		Metrics: m,
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
	}).Handler())
	defer proxyServer.Close()

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: func(*http.Request) (*url.URL, error) {
				return url.Parse(proxyServer.URL)
			},
		},
	}

	target := fmt.Sprintf("http://service.internal%s/healthz", upstreamURL.Host[strings.LastIndex(upstreamURL.Host, ":"):])
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do() error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}
	if receivedHost == "" || !strings.HasPrefix(receivedHost, "service.internal:") {
		t.Fatalf("received host = %q, want service.internal:<port>", receivedHost)
	}
}

func TestProxyEstablishesConnectTunnel(t *testing.T) {
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer upstream.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, acceptErr := upstream.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 4)
		_, _ = io.ReadFull(conn, buf)
		_, _ = conn.Write([]byte("pong"))
	}()

	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	proxyServer := httptest.NewServer(NewServer(Dependencies{
		Resolver: staticResolver{
			lookup: map[string][]net.IP{
				"tunnel.internal": {net.ParseIP("127.0.0.1")},
			},
		},
		Metrics: m,
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
	}).Handler())
	defer proxyServer.Close()

	proxyURL, err := url.Parse(proxyServer.URL)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	conn, err := net.Dial("tcp", proxyURL.Host)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer conn.Close()

	target := fmt.Sprintf("tunnel.internal:%s", strings.TrimPrefix(upstream.Addr().String(), "127.0.0.1:"))
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		t.Fatalf("Fprintf() error = %v", err)
	}

	reader := bufio.NewReader(conn)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("ReadString() error = %v", err)
	}
	if !strings.Contains(statusLine, "200") {
		t.Fatalf("unexpected status line %q", statusLine)
	}

	for {
		line, readErr := reader.ReadString('\n')
		if readErr != nil {
			t.Fatalf("reading headers: %v", readErr)
		}
		if line == "\r\n" {
			break
		}
	}

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	reply := make([]byte, 4)
	if _, err := io.ReadFull(reader, reply); err != nil {
		t.Fatalf("ReadFull() error = %v", err)
	}
	if string(reply) != "pong" {
		t.Fatalf("reply = %q, want %q", string(reply), "pong")
	}

	<-done
}

type staticResolver struct {
	lookup map[string][]net.IP
}

func (s staticResolver) LookupNetIP(_ context.Context, host string) ([]net.IP, error) {
	ips, ok := s.lookup[host]
	if !ok {
		return nil, fmt.Errorf("host not found: %s", host)
	}
	return ips, nil
}
