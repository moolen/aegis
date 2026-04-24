package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/moolen/aegis/internal/config"
	appmetrics "github.com/moolen/aegis/internal/metrics"
	"github.com/moolen/aegis/internal/proxy"
)

type reloadableProxyHandler struct {
	current atomic.Value
}

func (h *reloadableProxyHandler) Swap(next http.Handler) {
	h.current.Store(next)
}

func (h *reloadableProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	current, _ := h.current.Load().(http.Handler)
	if current == nil {
		http.Error(w, "proxy handler unavailable", http.StatusServiceUnavailable)
		return
	}
	current.ServeHTTP(w, r)
}

type runtimeManager struct {
	rootCtx    context.Context
	logger     *slog.Logger
	metrics    *appmetrics.Metrics
	configPath string
	handler    *reloadableProxyHandler

	mu      sync.Mutex
	current runtimeGeneration
}

type runtimeGeneration struct {
	cfg    config.Config
	cancel context.CancelFunc
	mitm   *proxy.MITMEngine
}

func newRuntimeManager(rootCtx context.Context, logger *slog.Logger, metrics *appmetrics.Metrics, configPath string, handler *reloadableProxyHandler) *runtimeManager {
	return &runtimeManager{
		rootCtx:    rootCtx,
		logger:     logger,
		metrics:    metrics,
		configPath: configPath,
		handler:    handler,
	}
}

func (m *runtimeManager) LoadInitial(cfg config.Config) error {
	return m.applyConfig(cfg, false)
}

func (m *runtimeManager) ReloadFromFile() error {
	cfg, err := loadRuntimeConfig(m.configPath)
	if err != nil {
		m.recordReloadResult("error")
		return err
	}

	if err := m.applyConfig(cfg, true); err != nil {
		m.recordReloadResult("error")
		return err
	}

	m.recordReloadResult("success")
	return nil
}

func (m *runtimeManager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.current.cancel != nil {
		m.current.cancel()
		m.current.cancel = nil
	}
}

func (m *runtimeManager) applyConfig(cfg config.Config, enforceImmutable bool) error {
	if err := validateRuntimeConfig(cfg); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if enforceImmutable {
		if err := validateReloadableConfig(m.current.cfg, cfg); err != nil {
			return err
		}
	}

	generationCtx, cancel := context.WithCancel(m.rootCtx)
	deps, err := buildProxyDependencies(generationCtx, cfg, m.logger, m.metrics)
	if err != nil {
		cancel()
		return err
	}

	nextHandler := newProxyServer(deps).Handler()
	m.handler.Swap(nextHandler)

	m.recordMITMLifecycle(m.current.mitm, deps.MITM, enforceImmutable)

	if m.current.cancel != nil {
		m.current.cancel()
	}
	m.current = runtimeGeneration{
		cfg:    cfg,
		cancel: cancel,
		mitm:   deps.MITM,
	}

	return nil
}

func (m *runtimeManager) recordReloadResult(result string) {
	if m.metrics == nil {
		return
	}
	m.metrics.ConfigReloadsTotal.WithLabelValues(result).Inc()
}

func (m *runtimeManager) recordMITMLifecycle(previous *proxy.MITMEngine, next *proxy.MITMEngine, isReload bool) {
	result := "disabled"
	switch {
	case previous == nil && next == nil:
		return
	case previous == nil && next != nil:
		if isReload {
			result = "enabled"
		} else {
			result = "initial"
		}
	case previous != nil && next == nil:
		result = "disabled"
	case previous.Fingerprint() == next.Fingerprint():
		result = "unchanged"
	default:
		result = "rotated"
	}

	if m.metrics != nil {
		m.metrics.MITMCACyclesTotal.WithLabelValues(result).Inc()
	}

	switch result {
	case "initial":
		m.logger.Info("mitm ca loaded", "fingerprint", next.Fingerprint())
	case "enabled":
		m.logger.Info("mitm ca enabled", "fingerprint", next.Fingerprint())
	case "disabled":
		m.logger.Info("mitm ca disabled")
	case "unchanged":
		m.logger.Info("mitm ca reloaded without fingerprint change", "fingerprint", next.Fingerprint())
	case "rotated":
		m.logger.Info("mitm ca rotated", "previous_fingerprint", previous.Fingerprint(), "fingerprint", next.Fingerprint())
	}

	if previous != nil {
		evictions := previous.CacheEntries()
		if evictions > 0 && m.metrics != nil {
			reason := "reload"
			if next == nil {
				reason = "disabled"
			} else if result == "rotated" {
				reason = "rotation"
			}
			m.metrics.MITMCertificateCacheEvictions.WithLabelValues(reason).Add(float64(evictions))
			m.logger.Info("mitm certificate cache reset", "reason", reason, "entries", evictions)
		}
	}
}

func loadRuntimeConfig(path string) (config.Config, error) {
	cfg, err := config.LoadFile(path)
	if err != nil {
		return config.Config{}, fmt.Errorf("load config: %w", err)
	}
	if err := validateRuntimeConfig(cfg); err != nil {
		return config.Config{}, err
	}
	return cfg, nil
}

func validateRuntimeConfig(cfg config.Config) error {
	if len(cfg.Policies) == 0 {
		return fmt.Errorf("policies must contain at least one entry to enable plain HTTP policy enforcement safely")
	}
	return nil
}

func validateReloadableConfig(current config.Config, next config.Config) error {
	if current.Proxy.Listen != next.Proxy.Listen {
		return fmt.Errorf("proxy.listen cannot change during reload")
	}
	if current.Metrics.Listen != next.Metrics.Listen {
		return fmt.Errorf("metrics.listen cannot change during reload")
	}
	if current.Proxy.ProxyProtocol.Enabled != next.Proxy.ProxyProtocol.Enabled {
		return fmt.Errorf("proxy.proxyProtocol.enabled cannot change during reload")
	}
	if proxyProtocolTimeoutForConfig(current.Proxy.ProxyProtocol) != proxyProtocolTimeoutForConfig(next.Proxy.ProxyProtocol) {
		return fmt.Errorf("proxy.proxyProtocol.headerTimeout cannot change during reload")
	}
	return nil
}

func proxyProtocolTimeoutForConfig(cfg config.ProxyProtocolConfig) int64 {
	if cfg.HeaderTimeout == nil {
		return proxyProtocolHeaderTimeout.Nanoseconds()
	}
	return cfg.HeaderTimeout.Nanoseconds()
}
