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
	"github.com/moolen/aegis/internal/identity"
	appmetrics "github.com/moolen/aegis/internal/metrics"
	"github.com/moolen/aegis/internal/policy"
	"github.com/moolen/aegis/internal/proxy"
)

var newKubernetesRuntimeProvider = func(cfg config.KubernetesDiscoveryConfig, logger *slog.Logger) (identity.RuntimeProvider, error) {
	return identity.NewKubernetesRuntimeProvider(cfg, logger)
}

var newProxyServer = func(deps proxy.Dependencies) interface{ Handler() http.Handler } {
	return proxy.NewServer(deps)
}

var discoveryProviderStartupTimeout = 30 * time.Second

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
	if len(cfg.Policies) == 0 {
		logger.Error("load config failed", "error", "policies must contain at least one entry to enable plain HTTP policy enforcement safely")
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	proxySrv, metricsSrv, err := buildServers(ctx, cfg, logger)
	if err != nil {
		logger.Error("build servers failed", "error", err)
		return 1
	}

	errCh := make(chan error, 2)

	go serve(logger, "proxy", proxySrv, errCh)
	go serve(logger, "metrics", metricsSrv, errCh)

	logger.Info("aegis started", "proxy_listen", cfg.Proxy.Listen, "metrics_listen", cfg.Metrics.Listen)

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

func buildServers(ctx context.Context, cfg config.Config, logger *slog.Logger) (*http.Server, *http.Server, error) {
	registry := prometheus.NewRegistry()
	m := appmetrics.New(registry)
	resolver := dns.NewResolver(dns.Config{
		CacheTTL: cfg.DNS.CacheTTL,
		Timeout:  cfg.DNS.Timeout,
		Servers:  cfg.DNS.Servers,
	}, nil, logger, m)
	engine, err := policy.NewEngine(cfg.Policies)
	if err != nil {
		return nil, nil, fmt.Errorf("compile policy engine: %w", err)
	}
	identityResolver, err := buildIdentityResolver(ctx, cfg.Discovery, logger, m)
	if err != nil {
		return nil, nil, fmt.Errorf("build identity resolver: %w", err)
	}

	proxyHandler := newProxyServer(proxy.Dependencies{
		Resolver:         resolver,
		IdentityResolver: identityResolver,
		PolicyEngine:     engine,
		Metrics:          m,
		Logger:           logger,
	})
	metricsHandler := appmetrics.NewServer(cfg.Metrics.Listen, registry)

	return &http.Server{
			Addr:              cfg.Proxy.Listen,
			Handler:           proxyHandler.Handler(),
			ReadHeaderTimeout: 10 * time.Second,
		}, &http.Server{
			Addr:              cfg.Metrics.Listen,
			Handler:           metricsHandler.Handler(),
			ReadHeaderTimeout: 5 * time.Second,
		}, nil
}

func buildIdentityResolver(ctx context.Context, cfg config.DiscoveryConfig, logger *slog.Logger, m *appmetrics.Metrics) (proxy.IdentityResolver, error) {
	if len(cfg.Kubernetes) == 0 {
		return nil, nil
	}

	active := make([]identity.ProviderHandle, 0, len(cfg.Kubernetes))
	for _, kubeCfg := range cfg.Kubernetes {
		logger.Info("starting discovery provider", "provider", kubeCfg.Name, "kind", "kubernetes")

		handle, err := newKubernetesRuntimeProvider(kubeCfg, logger)
		if err != nil {
			logger.Warn("discovery provider build failed", "provider", kubeCfg.Name, "kind", "kubernetes", "error", err)
			if m != nil {
				m.DiscoveryProviderFailuresTotal.WithLabelValues(kubeCfg.Name, "kubernetes", "build").Inc()
			}
			continue
		}

		if m != nil {
			m.DiscoveryProviderStartsTotal.WithLabelValues(handle.Name, handle.Kind).Inc()
		}

		if err := handle.Provider.Start(ctx, discoveryProviderStartupTimeout); err != nil {
			logger.Warn("discovery provider start failed", "provider", handle.Name, "kind", handle.Kind, "error", err)
			if m != nil {
				m.DiscoveryProviderFailuresTotal.WithLabelValues(handle.Name, handle.Kind, "start").Inc()
			}
			continue
		}

		active = append(active, identity.ProviderHandle{
			Name:     handle.Name,
			Kind:     handle.Kind,
			Resolver: handle.Provider,
		})
		logger.Info("discovery provider active", "provider", handle.Name, "kind", handle.Kind)
	}

	if len(active) == 0 {
		if len(cfg.Kubernetes) > 0 {
			return nil, fmt.Errorf("discovery configured but no providers became active")
		}
		return nil, nil
	}

	if m != nil {
		m.DiscoveryProvidersActive.Set(float64(len(active)))
	}

	return identity.NewCompositeResolver(active, logger, m), nil
}

var _ interface {
	LookupNetIP(context.Context, string) ([]net.IP, error)
} = (*dns.Resolver)(nil)
