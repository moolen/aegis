package runtime

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/moolen/aegis/internal/config"
	appmetrics "github.com/moolen/aegis/internal/metrics"
	"github.com/moolen/aegis/internal/proxy"
)

var listen = func(network string, address string) (net.Listener, error) {
	return net.Listen(network, address)
}

var proxyProtocolHeaderTimeout = 5 * time.Second

func serve(logger *slog.Logger, name string, srv *http.Server, listener net.Listener, errCh chan<- error) {
	logger.Info("server listening", "name", name, "addr", listener.Addr().String())
	err := srv.Serve(listener)
	if err != nil && err != http.ErrServerClosed {
		errCh <- fmt.Errorf("%s server: %w", name, err)
		return
	}
	errCh <- nil
}

func shutdownServer(logger *slog.Logger, name string, srv *http.Server, ctx context.Context) error {
	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("shutdown failed", "name", name, "error", err)
		return fmt.Errorf("shutdown %s server: %w", name, err)
	}
	return nil
}

var shutdownHTTPServer = shutdownServer

func newHTTPServers(cfg config.Config, proxyHandler http.Handler, metricsHandler http.Handler, adminHandler http.Handler, pprofHandler http.Handler) (*http.Server, *http.Server, *http.Server, *http.Server) {
	var adminSrv *http.Server
	if adminHandler != nil {
		adminSrv = &http.Server{
			Addr:              cfg.Admin.Listen,
			Handler:           adminHandler,
			ReadHeaderTimeout: 5 * time.Second,
		}
	}
	var pprofSrv *http.Server
	if pprofHandler != nil {
		pprofSrv = &http.Server{
			Addr:              cfg.Pprof.Listen,
			Handler:           pprofHandler,
			ReadHeaderTimeout: 5 * time.Second,
		}
	}
	return &http.Server{
			Addr:              cfg.Proxy.Listen,
			Handler:           proxyHandler,
			ReadHeaderTimeout: 10 * time.Second,
		}, &http.Server{
			Addr:              cfg.Metrics.Listen,
			Handler:           metricsHandler,
			ReadHeaderTimeout: 5 * time.Second,
		}, adminSrv, pprofSrv
}

func buildListeners(cfg config.Config, logger *slog.Logger, m *appmetrics.Metrics) (net.Listener, net.Listener, net.Listener, net.Listener, error) {
	proxyListener, err := listen("tcp", cfg.Proxy.Listen)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("listen proxy: %w", err)
	}

	if cfg.Proxy.ProxyProtocol.Enabled {
		headerTimeout := proxyProtocolHeaderTimeout
		if cfg.Proxy.ProxyProtocol.HeaderTimeout != nil {
			headerTimeout = *cfg.Proxy.ProxyProtocol.HeaderTimeout
		}
		trustedCIDRs, err := parseTrustedProxyProtocolCIDRs(cfg.Proxy.ProxyProtocol.TrustedCIDRs)
		if err != nil {
			proxyListener.Close()
			return nil, nil, nil, nil, fmt.Errorf("parse proxy protocol trusted CIDRs: %w", err)
		}
		proxyListener = proxy.NewProxyProtocolListener(proxyListener, proxy.ProxyProtocolListenerConfig{
			HeaderTimeout: headerTimeout,
			Logger:        logger,
			Metrics:       m,
			TrustedCIDRs:  trustedCIDRs,
		})
	}

	metricsListener, err := listen("tcp", cfg.Metrics.Listen)
	if err != nil {
		proxyListener.Close()
		return nil, nil, nil, nil, fmt.Errorf("listen metrics: %w", err)
	}

	var adminListener net.Listener
	if cfg.Admin.Enabled {
		adminListener, err = listen("tcp", cfg.Admin.Listen)
		if err != nil {
			proxyListener.Close()
			metricsListener.Close()
			return nil, nil, nil, nil, fmt.Errorf("listen admin: %w", err)
		}
	}

	var pprofListener net.Listener
	if cfg.Pprof.Enabled {
		pprofListener, err = listen("tcp", cfg.Pprof.Listen)
		if err != nil {
			proxyListener.Close()
			metricsListener.Close()
			if adminListener != nil {
				adminListener.Close()
			}
			return nil, nil, nil, nil, fmt.Errorf("listen pprof: %w", err)
		}
	}

	return proxyListener, metricsListener, adminListener, pprofListener, nil
}

func parseTrustedProxyProtocolCIDRs(values []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, err
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}
