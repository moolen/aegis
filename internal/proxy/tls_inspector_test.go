package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"net"
	"testing"
	"time"
)

func TestReadClientHelloExtractsSNI(t *testing.T) {
	clientHello := mustClientHello(t, "example.com")

	raw, sni, err := readClientHello(bufio.NewReader(bytes.NewReader(clientHello)))
	if err != nil {
		t.Fatalf("readClientHello() error = %v", err)
	}
	if sni != "example.com" {
		t.Fatalf("sni = %q, want %q", sni, "example.com")
	}
	if string(raw) != string(clientHello) {
		t.Fatal("raw client hello did not round-trip")
	}
}

func TestReadClientHelloReturnsMissingSNI(t *testing.T) {
	clientHello := mustClientHello(t, "")

	_, _, err := readClientHello(bufio.NewReader(bytes.NewReader(clientHello)))
	if !errors.Is(err, errTLSSNIMissing) {
		t.Fatalf("readClientHello() error = %v, want errTLSSNIMissing", err)
	}
}

func mustClientHello(t *testing.T, serverName string) []byte {
	t.Helper()

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()

	helloCh := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 4096)
		n, _ := serverConn.Read(buf)
		helloCh <- append([]byte(nil), buf[:n]...)
	}()

	tlsClient := tls.Client(clientConn, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         serverName,
		MinVersion:         tls.VersionTLS12,
	})
	go func() {
		_ = tlsClient.Handshake()
		_ = clientConn.Close()
	}()

	select {
	case hello := <-helloCh:
		if len(hello) == 0 {
			t.Fatal("captured empty client hello")
		}
		return hello
	case <-time.After(2 * time.Second):
		t.Fatal("timed out capturing client hello")
		return nil
	}
}
