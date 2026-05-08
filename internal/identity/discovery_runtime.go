package identity

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/moolen/aegis/internal/config"
	appmetrics "github.com/moolen/aegis/internal/metrics"
)

const defaultDiscoveryProviderStartupTimeout = 30 * time.Second

type discoveryRuntimeDeps struct {
	startupTimeout               time.Duration
	newKubernetesRuntimeProvider func(config.KubernetesDiscoveryConfig, *slog.Logger) (RuntimeProvider, error)
	newEC2RuntimeProvider        func(config.EC2DiscoveryConfig, *slog.Logger) (RuntimeProvider, error)
}

func defaultDiscoveryRuntimeDeps() discoveryRuntimeDeps {
	return discoveryRuntimeDeps{
		startupTimeout:               defaultDiscoveryProviderStartupTimeout,
		newKubernetesRuntimeProvider: NewKubernetesRuntimeProvider,
		newEC2RuntimeProvider:        NewEC2RuntimeProvider,
	}
}

type DiscoveryRuntime struct {
	cfg     config.DiscoveryConfig
	logger  *slog.Logger
	metrics *appmetrics.Metrics
	deps    discoveryRuntimeDeps
}

func NewDiscoveryRuntime(cfg config.DiscoveryConfig, logger *slog.Logger, metrics *appmetrics.Metrics) *DiscoveryRuntime {
	return newDiscoveryRuntime(cfg, logger, metrics, defaultDiscoveryRuntimeDeps())
}

func newDiscoveryRuntime(cfg config.DiscoveryConfig, logger *slog.Logger, metrics *appmetrics.Metrics, deps discoveryRuntimeDeps) *DiscoveryRuntime {
	if logger == nil {
		logger = slog.Default()
	}
	if deps.startupTimeout <= 0 {
		deps.startupTimeout = defaultDiscoveryProviderStartupTimeout
	}
	if deps.newKubernetesRuntimeProvider == nil {
		deps.newKubernetesRuntimeProvider = NewKubernetesRuntimeProvider
	}
	if deps.newEC2RuntimeProvider == nil {
		deps.newEC2RuntimeProvider = NewEC2RuntimeProvider
	}

	return &DiscoveryRuntime{
		cfg:     cfg,
		logger:  logger,
		metrics: metrics,
		deps:    deps,
	}
}

func (r *DiscoveryRuntime) Start(ctx context.Context) (*CompositeResolver, error) {
	if len(r.cfg.Kubernetes) == 0 && len(r.cfg.EC2) == 0 {
		return nil, nil
	}

	active := make([]ProviderHandle, 0, len(r.cfg.Kubernetes)+len(r.cfg.EC2))
	for _, kubeCfg := range r.cfg.Kubernetes {
		handle, ok := r.startKubernetesProvider(ctx, kubeCfg)
		if !ok {
			continue
		}
		active = append(active, handle)
	}
	for _, ec2Cfg := range r.cfg.EC2 {
		handle, ok := r.startEC2Provider(ctx, ec2Cfg)
		if !ok {
			continue
		}
		active = append(active, handle)
	}

	if len(active) == 0 {
		return nil, fmt.Errorf("discovery configured but no providers became active")
	}

	if r.metrics != nil {
		r.metrics.DiscoveryProvidersActive.Set(float64(len(active)))
	}

	return NewCompositeResolver(active, r.logger, r.metrics), nil
}

func (r *DiscoveryRuntime) startKubernetesProvider(ctx context.Context, cfg config.KubernetesDiscoveryConfig) (ProviderHandle, bool) {
	r.logger.Info("starting discovery provider", "provider", cfg.Name, "kind", "kubernetes")

	handle, err := r.deps.newKubernetesRuntimeProvider(cfg, r.logger)
	if err != nil {
		r.logger.Warn("discovery provider build failed", "provider", cfg.Name, "kind", "kubernetes", "error", err)
		if r.metrics != nil {
			r.metrics.DiscoveryProviderFailuresTotal.WithLabelValues(cfg.Name, "kubernetes", "build").Inc()
		}
		return ProviderHandle{}, false
	}

	return r.activateProvider(ctx, handle)
}

func (r *DiscoveryRuntime) startEC2Provider(ctx context.Context, cfg config.EC2DiscoveryConfig) (ProviderHandle, bool) {
	r.logger.Info("starting discovery provider", "provider", cfg.Name, "kind", "ec2")

	handle, err := r.deps.newEC2RuntimeProvider(cfg, r.logger)
	if err != nil {
		r.logger.Warn("discovery provider build failed", "provider", cfg.Name, "kind", "ec2", "error", err)
		if r.metrics != nil {
			r.metrics.DiscoveryProviderFailuresTotal.WithLabelValues(cfg.Name, "ec2", "build").Inc()
		}
		return ProviderHandle{}, false
	}

	return r.activateProvider(ctx, handle)
}

func (r *DiscoveryRuntime) activateProvider(ctx context.Context, handle RuntimeProvider) (ProviderHandle, bool) {
	if r.metrics != nil {
		r.metrics.DiscoveryProviderStartsTotal.WithLabelValues(handle.Name, handle.Kind).Inc()
	}
	if attachable, ok := handle.Provider.(interface{ AttachMetrics(*appmetrics.Metrics) }); ok {
		attachable.AttachMetrics(r.metrics)
	}

	if err := handle.Provider.Start(ctx, r.deps.startupTimeout); err != nil {
		r.logger.Warn("discovery provider start failed", "provider", handle.Name, "kind", handle.Kind, "error", err)
		if r.metrics != nil {
			r.metrics.DiscoveryProviderFailuresTotal.WithLabelValues(handle.Name, handle.Kind, "start").Inc()
		}
		return ProviderHandle{}, false
	}

	r.logger.Info("discovery provider active", "provider", handle.Name, "kind", handle.Kind)
	return ProviderHandle{
		Name:     handle.Name,
		Kind:     handle.Kind,
		Resolver: handle.Provider,
	}, true
}
