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

var newEC2RuntimeProvider = func(cfg config.EC2DiscoveryConfig, logger *slog.Logger) (identity.RuntimeProvider, error) {
	return identity.NewEC2RuntimeProvider(cfg, logger)
}

var newMITMEngineFromFiles = func(certFile string, keyFile string, logger *slog.Logger) (*proxy.MITMEngine, error) {
	return proxy.NewMITMEngineFromFiles(certFile, keyFile, logger)
}

var newProxyServer = func(deps proxy.Dependencies) interface{ Handler() http.Handler } {
	return proxy.NewServer(deps)
}

var listen = func(network string, address string) (net.Listener, error) {
	return net.Listen(network, address)
}

var discoveryProviderStartupTimeout = 30 * time.Second
var proxyProtocolHeaderTimeout = 5 * time.Second

func main() {
	os.Exit(run())
}

func run() int {
	var configPath string
	flag.StringVar(&configPath, "config", "aegis.example.yaml", "Path to the Aegis configuration file.")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := loadRuntimeConfig(configPath)
	if err != nil {
		logger.Error("load config failed", "path", configPath, "error", err)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	registry := prometheus.NewRegistry()
	m := appmetrics.New(registry)
	drainTracker := proxy.NewDrainTracker(logger, m)
	reloadableHandler := &reloadableProxyHandler{}
	runtime := newRuntimeManager(ctx, logger, m, configPath, reloadableHandler, drainTracker)
	defer runtime.Close()
	if err := runtime.LoadInitial(cfg); err != nil {
		logger.Error("build runtime failed", "error", err)
		return 1
	}

	proxySrv, metricsSrv := newHTTPServers(cfg, reloadableHandler, appmetrics.NewServer(cfg.Metrics.Listen, registry).Handler())
	proxyListener, metricsListener, err := buildListeners(cfg, logger, m)
	if err != nil {
		logger.Error("build listeners failed", "error", err)
		return 1
	}
	defer proxyListener.Close()
	defer metricsListener.Close()

	errCh := make(chan error, 2)
	reloadCh := make(chan os.Signal, 1)
	signal.Notify(reloadCh, syscall.SIGHUP)
	defer signal.Stop(reloadCh)

	go serve(logger, "proxy", proxySrv, proxyListener, errCh)
	go serve(logger, "metrics", metricsSrv, metricsListener, errCh)

	logger.Info("aegis started", "proxy_listen", cfg.Proxy.Listen, "metrics_listen", cfg.Metrics.Listen)

	for {
		select {
		case err := <-errCh:
			if err != nil {
				logger.Error("server exited with error", "error", err)
				return 1
			}
			return 0
		case <-reloadCh:
			if err := runtime.ReloadFromFile(); err != nil {
				logger.Error("reload config failed", "path", configPath, "error", err)
				continue
			}
			logger.Info("config reloaded", "path", configPath)
		case <-ctx.Done():
			logger.Info("shutdown signal received")
			goto shutdown
		}
	}

shutdown:
	shutdownCtx, cancel := context.WithTimeout(context.Background(), runtime.ShutdownGracePeriod())
	defer cancel()

	if err := shutdownServer(logger, "proxy", proxySrv, shutdownCtx); err != nil {
		return 1
	}
	if err := shutdownServer(logger, "metrics", metricsSrv, shutdownCtx); err != nil {
		return 1
	}
	drainResult := drainTracker.Shutdown(shutdownCtx)
	logger.Info("aegis shutdown complete", "result", drainResult, "grace_period", runtime.ShutdownGracePeriod())

	logger.Info("aegis stopped")
	return 0
}

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

func buildServers(ctx context.Context, cfg config.Config, logger *slog.Logger) (*http.Server, *http.Server, *appmetrics.Metrics, error) {
	registry := prometheus.NewRegistry()
	m := appmetrics.New(registry)
	deps, err := buildProxyDependencies(ctx, cfg, logger, m, proxy.NewDrainTracker(logger, m))
	if err != nil {
		return nil, nil, nil, err
	}
	proxyHandler := newProxyServer(deps)
	metricsHandler := appmetrics.NewServer(cfg.Metrics.Listen, registry)

	proxySrv, metricsSrv := newHTTPServers(cfg, proxyHandler.Handler(), metricsHandler.Handler())
	return proxySrv, metricsSrv, m, nil
}

func buildProxyDependencies(ctx context.Context, cfg config.Config, logger *slog.Logger, m *appmetrics.Metrics, drainTracker *proxy.DrainTracker) (proxy.Dependencies, error) {
	resolver := dns.NewResolver(dns.Config{
		CacheTTL: cfg.DNS.CacheTTL,
		Timeout:  cfg.DNS.Timeout,
		Servers:  cfg.DNS.Servers,
	}, nil, logger, m)
	destinationGuard, err := proxy.NewDestinationGuard(
		cfg.DNS.RebindingProtection.AllowedHostPatterns,
		cfg.DNS.RebindingProtection.AllowedCIDRs,
		logger,
	)
	if err != nil {
		return proxy.Dependencies{}, fmt.Errorf("build destination guard: %w", err)
	}
	engine, err := policy.NewEngine(cfg.Policies)
	if err != nil {
		return proxy.Dependencies{}, fmt.Errorf("compile policy engine: %w", err)
	}
	var mitmEngine *proxy.MITMEngine
	if cfg.Proxy.CA.CertFile != "" {
		mitmEngine, err = newMITMEngineFromFiles(cfg.Proxy.CA.CertFile, cfg.Proxy.CA.KeyFile, logger)
		if err != nil {
			return proxy.Dependencies{}, fmt.Errorf("load mitm engine: %w", err)
		}
		mitmEngine.AttachMetrics(m)
	}
	identityResolver, err := buildIdentityResolver(ctx, cfg.Discovery, logger, m)
	if err != nil {
		return proxy.Dependencies{}, fmt.Errorf("build identity resolver: %w", err)
	}

	return proxy.Dependencies{
		Resolver:         resolver,
		DestinationGuard: destinationGuard,
		DrainTracker:     drainTracker,
		AuditMode:        config.NormalizeEnforcementMode(cfg.Proxy.Enforcement) == config.EnforcementAudit,
		IdentityResolver: identityResolver,
		PolicyEngine:     engine,
		MITM:             mitmEngine,
		Metrics:          m,
		Logger:           logger,
	}, nil
}

func newHTTPServers(cfg config.Config, proxyHandler http.Handler, metricsHandler http.Handler) (*http.Server, *http.Server) {
	return &http.Server{
			Addr:              cfg.Proxy.Listen,
			Handler:           proxyHandler,
			ReadHeaderTimeout: 10 * time.Second,
		}, &http.Server{
			Addr:              cfg.Metrics.Listen,
			Handler:           metricsHandler,
			ReadHeaderTimeout: 5 * time.Second,
		}
}

func buildListeners(cfg config.Config, logger *slog.Logger, m *appmetrics.Metrics) (net.Listener, net.Listener, error) {
	proxyListener, err := listen("tcp", cfg.Proxy.Listen)
	if err != nil {
		return nil, nil, fmt.Errorf("listen proxy: %w", err)
	}

	if cfg.Proxy.ProxyProtocol.Enabled {
		headerTimeout := proxyProtocolHeaderTimeout
		if cfg.Proxy.ProxyProtocol.HeaderTimeout != nil {
			headerTimeout = *cfg.Proxy.ProxyProtocol.HeaderTimeout
		}
		proxyListener = proxy.NewProxyProtocolListener(proxyListener, proxy.ProxyProtocolListenerConfig{
			HeaderTimeout: headerTimeout,
			Logger:        logger,
			Metrics:       m,
		})
	}

	metricsListener, err := listen("tcp", cfg.Metrics.Listen)
	if err != nil {
		proxyListener.Close()
		return nil, nil, fmt.Errorf("listen metrics: %w", err)
	}

	return proxyListener, metricsListener, nil
}

func buildIdentityResolver(ctx context.Context, cfg config.DiscoveryConfig, logger *slog.Logger, m *appmetrics.Metrics) (proxy.IdentityResolver, error) {
	if len(cfg.Kubernetes) == 0 && len(cfg.EC2) == 0 {
		return nil, nil
	}

	active := make([]identity.ProviderHandle, 0, len(cfg.Kubernetes)+len(cfg.EC2))
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
		if attachable, ok := handle.Provider.(interface{ AttachMetrics(*appmetrics.Metrics) }); ok {
			attachable.AttachMetrics(m)
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
	for _, ec2Cfg := range cfg.EC2 {
		logger.Info("starting discovery provider", "provider", ec2Cfg.Name, "kind", "ec2")

		handle, err := newEC2RuntimeProvider(ec2Cfg, logger)
		if err != nil {
			logger.Warn("discovery provider build failed", "provider", ec2Cfg.Name, "kind", "ec2", "error", err)
			if m != nil {
				m.DiscoveryProviderFailuresTotal.WithLabelValues(ec2Cfg.Name, "ec2", "build").Inc()
			}
			continue
		}

		if m != nil {
			m.DiscoveryProviderStartsTotal.WithLabelValues(handle.Name, handle.Kind).Inc()
		}
		if attachable, ok := handle.Provider.(interface{ AttachMetrics(*appmetrics.Metrics) }); ok {
			attachable.AttachMetrics(m)
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
		if len(cfg.Kubernetes) > 0 || len(cfg.EC2) > 0 {
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
