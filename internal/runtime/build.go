package runtime

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/moolen/aegis/internal/config"
	"github.com/moolen/aegis/internal/dns"
	appmetrics "github.com/moolen/aegis/internal/metrics"
	"github.com/moolen/aegis/internal/policy"
	"github.com/moolen/aegis/internal/proxy"
)

var newMITMEngineFromFiles = func(certFile string, keyFile string, logger *slog.Logger) (*proxy.MITMEngine, error) {
	return proxy.NewMITMEngineFromFiles(certFile, keyFile, logger)
}

var newProxyServer = func(deps proxy.Dependencies) interface{ Handler() http.Handler } {
	return proxy.NewServer(deps)
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
