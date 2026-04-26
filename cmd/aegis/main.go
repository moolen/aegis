package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
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
	os.Exit(runCLI(os.Args[1:]))
}

func run() int {
	return runServe(os.Args[1:])
}

func runServe(args []string) int {
	fs := newFlagSet("aegis")
	configPath := fs.String("config", "aegis.example.yaml", "Path to the Aegis configuration file.")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 2
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := loadRuntimeConfig(*configPath)
	if err != nil {
		logger.Error("load config failed", "path", *configPath, "error", err)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	registry := prometheus.NewRegistry()
	m := appmetrics.New(registry)
	drainTracker := proxy.NewDrainTracker(logger, m)
	reloadableHandler := &reloadableProxyHandler{}
	runtime := newRuntimeManager(ctx, logger, m, *configPath, reloadableHandler, drainTracker)
	defer runtime.Close()
	if err := runtime.LoadInitial(cfg); err != nil {
		logger.Error("build runtime failed", "error", err)
		return 1
	}

	metricsHandler := appmetrics.NewServer(cfg.Metrics.Listen, registry, runtime, nil).Handler()
	var adminHandler http.Handler
	if cfg.Admin.Enabled {
		adminHandler = appmetrics.NewAdminServer(cfg.Admin.Listen, runtime).Handler()
	}
	var pprofHandler http.Handler
	if cfg.Pprof.Enabled {
		pprofHandler = appmetrics.NewPprofServer(cfg.Pprof.Listen).Handler()
	}
	proxySrv, metricsSrv, adminSrv, pprofSrv := newHTTPServers(cfg, reloadableHandler, metricsHandler, adminHandler, pprofHandler)
	proxyListener, metricsListener, adminListener, pprofListener, err := buildListeners(cfg, logger, m)
	if err != nil {
		logger.Error("build listeners failed", "error", err)
		return 1
	}
	defer proxyListener.Close()
	defer metricsListener.Close()
	if adminListener != nil {
		defer adminListener.Close()
	}
	if pprofListener != nil {
		defer pprofListener.Close()
	}

	errCh := make(chan error, 4)
	reloadCh := make(chan os.Signal, 1)
	signal.Notify(reloadCh, syscall.SIGHUP)
	defer signal.Stop(reloadCh)

	go serve(logger, "proxy", proxySrv, proxyListener, errCh)
	go serve(logger, "metrics", metricsSrv, metricsListener, errCh)
	if adminSrv != nil && adminListener != nil {
		go serve(logger, "admin", adminSrv, adminListener, errCh)
	}
	if pprofSrv != nil && pprofListener != nil {
		go serve(logger, "pprof", pprofSrv, pprofListener, errCh)
	}

	startAttrs := []any{"proxy_listen", cfg.Proxy.Listen, "metrics_listen", cfg.Metrics.Listen}
	if cfg.Admin.Enabled {
		startAttrs = append(startAttrs, "admin_listen", cfg.Admin.Listen)
	}
	if cfg.Pprof.Enabled {
		startAttrs = append(startAttrs, "pprof_listen", cfg.Pprof.Listen)
	}
	logger.Info("aegis started", startAttrs...)

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
				logger.Error("reload config failed", "path", *configPath, "error", err)
				continue
			}
			logger.Info("config reloaded", "path", *configPath)
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
	if adminSrv != nil {
		if err := shutdownServer(logger, "admin", adminSrv, shutdownCtx); err != nil {
			return 1
		}
	}
	if pprofSrv != nil {
		if err := shutdownServer(logger, "pprof", pprofSrv, shutdownCtx); err != nil {
			return 1
		}
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

func buildServers(ctx context.Context, cfg config.Config, logger *slog.Logger) (*http.Server, *http.Server, *http.Server, *http.Server, *appmetrics.Metrics, error) {
	registry := prometheus.NewRegistry()
	m := appmetrics.New(registry)
	connectionLimiter := proxy.NewConnectionLimiter(logger, m)
	enforcement := proxy.NewEnforcementOverrideController(logger)
	deps, err := buildProxyDependencies(ctx, cfg, logger, m, proxy.NewDrainTracker(logger, m), connectionLimiter, enforcement)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	connectionLimiter.UpdateLimit(cfg.Proxy.ConnectionLimits.MaxConcurrentPerIdentity)
	proxyHandler := newProxyServer(deps)
	metricsHandler := appmetrics.NewServer(cfg.Metrics.Listen, registry, nil, nil)
	var adminHandler http.Handler
	if cfg.Admin.Enabled {
		adminHandler = appmetrics.NewAdminServer(cfg.Admin.Listen, nil).Handler()
	}
	var pprofHandler http.Handler
	if cfg.Pprof.Enabled {
		pprofHandler = appmetrics.NewPprofServer(cfg.Pprof.Listen).Handler()
	}

	proxySrv, metricsSrv, adminSrv, pprofSrv := newHTTPServers(cfg, proxyHandler.Handler(), metricsHandler.Handler(), adminHandler, pprofHandler)
	return proxySrv, metricsSrv, adminSrv, pprofSrv, m, nil
}

func buildProxyDependencies(ctx context.Context, cfg config.Config, logger *slog.Logger, m *appmetrics.Metrics, drainTracker *proxy.DrainTracker, connectionLimiter *proxy.ConnectionLimiter, enforcement *proxy.EnforcementOverrideController) (proxy.Dependencies, error) {
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
		mitmEngine.SetCacheMaxEntries(cfg.Proxy.CA.Cache.MaxEntries)
		for i, additional := range cfg.Proxy.CA.Additional {
			if err := mitmEngine.AddAdditionalCAFromFiles(additional.CertFile, additional.KeyFile); err != nil {
				return proxy.Dependencies{}, fmt.Errorf("load proxy.ca.additional[%d]: %w", i, err)
			}
		}
		mitmEngine.AttachMetrics(m)
	}
	identityResolver, err := buildIdentityResolver(ctx, cfg.Discovery, logger, m)
	if err != nil {
		return proxy.Dependencies{}, fmt.Errorf("build identity resolver: %w", err)
	}
	upstreamTLSConfig, err := buildUpstreamTLSConfig()
	if err != nil {
		return proxy.Dependencies{}, fmt.Errorf("build upstream tls config: %w", err)
	}

	return proxy.Dependencies{
		Resolver:              resolver,
		DestinationGuard:      destinationGuard,
		DrainTracker:          drainTracker,
		ConnectionLimiter:     connectionLimiter,
		ConnectionIdleTimeout: cfg.Proxy.IdleTimeout,
		UpstreamHTTPTransport: proxy.NewUpstreamHTTPTransport(),
		EnforcementMode:       cfg.Proxy.Enforcement,
		Enforcement:           enforcement,
		UnknownIdentityPolicy: cfg.Proxy.UnknownIdentityPolicy,
		IdentityResolver:      identityResolver,
		PolicyEngine:          engine,
		MITM:                  mitmEngine,
		UpstreamTLSConfig:     upstreamTLSConfig,
		Metrics:               m,
		Logger:                logger,
	}, nil
}

func buildUpstreamTLSConfig() (*tls.Config, error) {
	certFile := os.Getenv("SSL_CERT_FILE")
	if certFile == "" {
		return nil, nil
	}

	pemData, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("read SSL_CERT_FILE %q: %w", certFile, err)
	}
	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("load system cert pool: %w", err)
	}
	if pool == nil {
		pool = x509.NewCertPool()
	}
	if ok := pool.AppendCertsFromPEM(pemData); !ok {
		return nil, fmt.Errorf("append certificates from SSL_CERT_FILE %q: no certificates found", certFile)
	}

	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    pool,
	}, nil
}

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
