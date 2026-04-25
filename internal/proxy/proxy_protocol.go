package proxy

import (
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/moolen/aegis/internal/metrics"
)

var proxyProtocolV2Signature = []byte{
	0x0d, 0x0a, 0x0d, 0x0a,
	0x00, 0x0d, 0x0a, 0x51,
	0x55, 0x49, 0x54, 0x0a,
}

const defaultProxyProtocolHeaderTimeout = 5 * time.Second

const (
	proxyProtocolCommandLocal = 0x00
	proxyProtocolCommandProxy = 0x01

	proxyProtocolFamilyIPv4 = 0x01
	proxyProtocolFamilyIPv6 = 0x02

	proxyProtocolTransportStream = 0x01
)

var (
	errProxyProtocolInvalidSignature   = errors.New("invalid proxy protocol signature")
	errProxyProtocolUnsupportedVersion = errors.New("unsupported proxy protocol version")
	errProxyProtocolUnsupportedCommand = errors.New("unsupported proxy protocol command")
	errProxyProtocolUnsupportedFamily  = errors.New("unsupported proxy protocol address family")
	errProxyProtocolUnsupportedProto   = errors.New("unsupported proxy protocol transport protocol")
	errProxyProtocolTruncatedAddress   = errors.New("truncated proxy protocol address payload")
)

type ProxyProtocolListenerConfig struct {
	HeaderTimeout time.Duration
	Logger        *slog.Logger
	Metrics       *metrics.Metrics
}

func NewProxyProtocolListener(inner net.Listener, cfg ProxyProtocolListenerConfig) net.Listener {
	if cfg.HeaderTimeout <= 0 {
		cfg.HeaderTimeout = defaultProxyProtocolHeaderTimeout
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	return &proxyProtocolListener{
		Listener: inner,
		cfg:      cfg,
	}
}

type proxyProtocolListener struct {
	net.Listener
	cfg ProxyProtocolListenerConfig
}

func (l *proxyProtocolListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}

		proxyConn, ok := l.acceptProxyConn(conn)
		if ok {
			return proxyConn, nil
		}
	}
}

func (l *proxyProtocolListener) acceptProxyConn(conn net.Conn) (net.Conn, bool) {
	if err := conn.SetReadDeadline(time.Now().Add(l.cfg.HeaderTimeout)); err != nil {
		l.cfg.Logger.Debug("set proxy protocol read deadline failed", "remote_addr", conn.RemoteAddr().String(), "error", err)
	}

	header, err := readProxyProtocolV2Header(conn)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		result := "invalid"
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			result = "timeout"
		}
		if l.cfg.Metrics != nil {
			l.cfg.Metrics.ProxyProtocolConnectionsTotal.WithLabelValues(result).Inc()
		}
		l.cfg.Logger.Warn("proxy protocol header rejected", "remote_addr", conn.RemoteAddr().String(), "result", result, "error", err)
		conn.Close()
		return nil, false
	}

	if header.remoteAddr == nil {
		if l.cfg.Metrics != nil {
			l.cfg.Metrics.ProxyProtocolConnectionsTotal.WithLabelValues("local").Inc()
		}
		return conn, true
	}

	if l.cfg.Metrics != nil {
		l.cfg.Metrics.ProxyProtocolConnectionsTotal.WithLabelValues("accepted").Inc()
	}
	l.cfg.Logger.Debug("accepted proxy protocol connection", "remote_addr", header.remoteAddr.String(), "proxy_addr", conn.RemoteAddr().String())

	return &proxyProtocolConn{
		Conn:       conn,
		remoteAddr: header.remoteAddr,
	}, true
}

type proxyProtocolConn struct {
	net.Conn
	remoteAddr net.Addr
}

func (c *proxyProtocolConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

type proxyProtocolHeader struct {
	remoteAddr net.Addr
}

func readProxyProtocolV2Header(r io.Reader) (proxyProtocolHeader, error) {
	header := make([]byte, 16)
	if _, err := io.ReadFull(r, header); err != nil {
		return proxyProtocolHeader{}, err
	}

	if string(header[:12]) != string(proxyProtocolV2Signature) {
		return proxyProtocolHeader{}, errProxyProtocolInvalidSignature
	}

	version := header[12] >> 4
	if version != 0x02 {
		return proxyProtocolHeader{}, errProxyProtocolUnsupportedVersion
	}

	command := header[12] & 0x0f
	if command != proxyProtocolCommandLocal && command != proxyProtocolCommandProxy {
		return proxyProtocolHeader{}, errProxyProtocolUnsupportedCommand
	}

	family := header[13] >> 4
	transport := header[13] & 0x0f
	if command == proxyProtocolCommandLocal {
		payloadLength := int(binary.BigEndian.Uint16(header[14:16]))
		if payloadLength > 0 {
			payload := make([]byte, payloadLength)
			if _, err := io.ReadFull(r, payload); err != nil {
				return proxyProtocolHeader{}, err
			}
		}
		return proxyProtocolHeader{}, nil
	}

	if transport != proxyProtocolTransportStream {
		return proxyProtocolHeader{}, errProxyProtocolUnsupportedProto
	}

	payloadLength := int(binary.BigEndian.Uint16(header[14:16]))
	payload := make([]byte, payloadLength)
	if _, err := io.ReadFull(r, payload); err != nil {
		return proxyProtocolHeader{}, err
	}

	switch family {
	case proxyProtocolFamilyIPv4:
		if len(payload) < 12 {
			return proxyProtocolHeader{}, errProxyProtocolTruncatedAddress
		}
		ip := net.IP(payload[:4]).To4()
		if ip == nil {
			return proxyProtocolHeader{}, errProxyProtocolTruncatedAddress
		}
		port := int(binary.BigEndian.Uint16(payload[8:10]))
		return proxyProtocolHeader{remoteAddr: &net.TCPAddr{IP: ip, Port: port}}, nil
	case proxyProtocolFamilyIPv6:
		if len(payload) < 36 {
			return proxyProtocolHeader{}, errProxyProtocolTruncatedAddress
		}
		ip := net.IP(payload[:16]).To16()
		if ip == nil {
			return proxyProtocolHeader{}, errProxyProtocolTruncatedAddress
		}
		port := int(binary.BigEndian.Uint16(payload[32:34]))
		return proxyProtocolHeader{remoteAddr: &net.TCPAddr{IP: ip, Port: port}}, nil
	default:
		return proxyProtocolHeader{}, errProxyProtocolUnsupportedFamily
	}
}
