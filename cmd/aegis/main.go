package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/moolen/aegis/internal/config"
	"github.com/moolen/aegis/internal/dns"
	appmetrics "github.com/moolen/aegis/internal/metrics"
	"github.com/moolen/aegis/internal/proxy"
)

func main() {
	os.Exit(run())
}

func run() int {
	var configPath string
	flag.StringVar(&configPath, "config", "aegis.example.yaml", "Path to the Aegis configuration file.")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := config.LoadFile(configPath)
	if err != nil {
		logger.Error("load config failed", "path", configPath, "error", err)
		return 1
	}

	registry := prometheus.NewRegistry()
	m := appmetrics.New(registry)
	resolver := dns.NewResolver(dns.Config{
		CacheTTL: cfg.DNS.CacheTTL,
		Timeout:  cfg.DNS.Timeout,
		Servers:  cfg.DNS.Servers,
	}, nil, logger, m)

	proxyHandler := proxy.NewServer(proxy.Dependencies{
		Resolver: resolver,
		Metrics:  m,
		Logger:   logger,
	})
	metricsHandler := appmetrics.NewServer(cfg.Metrics.Listen, registry)

	proxySrv := &http.Server{
		Addr:              cfg.Proxy.Listen,
		Handler:           proxyHandler.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	metricsSrv := &http.Server{
		Addr:              cfg.Metrics.Listen,
		Handler:           metricsHandler.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	errCh := make(chan error, 2)

	go serve(logger, "proxy", proxySrv, errCh)
	go serve(logger, "metrics", metricsSrv, errCh)

	logger.Info("aegis started", "proxy_listen", cfg.Proxy.Listen, "metrics_listen", cfg.Metrics.Listen)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	select {
	case err := <-errCh:
		if err != nil {
			logger.Error("server exited with error", "error", err)
			return 1
		}
	case <-ctx.Done():
		logger.Info("shutdown signal received")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := shutdownServer(logger, "proxy", proxySrv, shutdownCtx); err != nil {
		return 1
	}
	if err := shutdownServer(logger, "metrics", metricsSrv, shutdownCtx); err != nil {
		return 1
	}

	logger.Info("aegis stopped")
	return 0
}

func serve(logger *slog.Logger, name string, srv *http.Server, errCh chan<- error) {
	logger.Info("server listening", "name", name, "addr", srv.Addr)
	err := srv.ListenAndServe()
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

var _ interface {
	LookupNetIP(context.Context, string) ([]net.IP, error)
} = (*dns.Resolver)(nil)
