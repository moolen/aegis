package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/moolen/aegis/internal/metrics"
)

func TestProxyProtocolListenerOverridesRemoteAddr(t *testing.T) {
	baseListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer baseListener.Close()

	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	listener := NewProxyProtocolListener(baseListener, ProxyProtocolListenerConfig{
		HeaderTimeout: time.Second,
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		Metrics:       m,
	})

	seenRemoteAddr := make(chan string, 1)
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			seenRemoteAddr <- r.RemoteAddr
			w.WriteHeader(http.StatusNoContent)
		}),
	}
	go func() {
		_ = srv.Serve(listener)
	}()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	conn, err := net.Dial("tcp", baseListener.Addr().String())
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer conn.Close()

	header := mustProxyProtocolV2Header(t, net.ParseIP("203.0.113.9"), 4567, net.ParseIP("127.0.0.1"), listener.Addr().(*net.TCPAddr).Port)
	if _, err := conn.Write(append(header, []byte("GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")...)); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	resp, err := http.ReadResponse(bufioNewReader(conn), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("ReadResponse() error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}

	if got := <-seenRemoteAddr; got != "203.0.113.9:4567" {
		t.Fatalf("remote addr = %q, want %q", got, "203.0.113.9:4567")
	}
	if got := counterValue(t, reg, "aegis_proxy_protocol_connections_total", map[string]string{"result": "accepted"}); got != 1 {
		t.Fatalf("accepted metric = %v, want 1", got)
	}
}

func TestProxyProtocolListenerRejectsInvalidHeaderAndContinues(t *testing.T) {
	baseListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer baseListener.Close()

	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	listener := NewProxyProtocolListener(baseListener, ProxyProtocolListenerConfig{
		HeaderTimeout: 200 * time.Millisecond,
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		Metrics:       m,
	})

	var hits atomic.Int32
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			w.WriteHeader(http.StatusNoContent)
		}),
	}
	go func() {
		_ = srv.Serve(listener)
	}()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	badConn, err := net.Dial("tcp", baseListener.Addr().String())
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	if _, err := badConn.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	_ = badConn.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 1)
	_, err = badConn.Read(buf)
	badConn.Close()
	if err == nil {
		t.Fatal("expected invalid proxy protocol connection to close")
	}

	goodConn, err := net.Dial("tcp", baseListener.Addr().String())
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer goodConn.Close()

	header := mustProxyProtocolV2Header(t, net.ParseIP("203.0.113.10"), 9876, net.ParseIP("127.0.0.1"), listener.Addr().(*net.TCPAddr).Port)
	if _, err := goodConn.Write(append(header, []byte("GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")...)); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	resp, err := http.ReadResponse(bufioNewReader(goodConn), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("ReadResponse() error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}
	if hits.Load() != 1 {
		t.Fatalf("hits = %d, want 1", hits.Load())
	}
	if got := counterValue(t, reg, "aegis_proxy_protocol_connections_total", map[string]string{"result": "invalid"}); got != 1 {
		t.Fatalf("invalid metric = %v, want 1", got)
	}
	if got := counterValue(t, reg, "aegis_proxy_protocol_connections_total", map[string]string{"result": "accepted"}); got != 1 {
		t.Fatalf("accepted metric = %v, want 1", got)
	}
}

func TestReadProxyProtocolV2HeaderParsesLocalCommand(t *testing.T) {
	header := append(append([]byte{}, proxyProtocolV2Signature...), 0x20, 0x00, 0x00, 0x00)
	parsed, err := readProxyProtocolV2Header(bytes.NewReader(header))
	if err != nil {
		t.Fatalf("readProxyProtocolV2Header() error = %v", err)
	}
	if parsed.remoteAddr != nil {
		t.Fatalf("remote addr = %#v, want nil", parsed.remoteAddr)
	}
}

func mustProxyProtocolV2Header(t *testing.T, sourceIP net.IP, sourcePort int, destinationIP net.IP, destinationPort int) []byte {
	t.Helper()

	source4 := sourceIP.To4()
	destination4 := destinationIP.To4()
	if source4 == nil || destination4 == nil {
		t.Fatal("mustProxyProtocolV2Header currently supports IPv4 only")
	}

	header := make([]byte, 16+12)
	copy(header[:12], proxyProtocolV2Signature)
	header[12] = 0x21
	header[13] = 0x11
	binary.BigEndian.PutUint16(header[14:16], uint16(12))
	copy(header[16:20], source4)
	copy(header[20:24], destination4)
	binary.BigEndian.PutUint16(header[24:26], uint16(sourcePort))
	binary.BigEndian.PutUint16(header[26:28], uint16(destinationPort))

	return header
}

func bufioNewReader(r io.Reader) *bufio.Reader {
	return bufio.NewReader(r)
}

func counterValue(t *testing.T, reg *prometheus.Registry, name string, labels map[string]string) float64 {
	t.Helper()

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v", err)
	}

	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.GetMetric() {
			if hasLabels(metric, labels) {
				if metric.Counter == nil {
					t.Fatalf("metric %q is not a counter", name)
				}
				return metric.Counter.GetValue()
			}
		}
	}

	t.Fatalf("metric %q with labels %#v not found", name, labels)
	return 0
}

func hasLabels(metric *dto.Metric, want map[string]string) bool {
	if len(metric.GetLabel()) != len(want) {
		return false
	}
	for _, pair := range metric.GetLabel() {
		if want[pair.GetName()] != pair.GetValue() {
			return false
		}
	}
	return true
}
