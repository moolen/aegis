package runtime

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/moolen/aegis/internal/config"
	"github.com/moolen/aegis/internal/identity"
	appmetrics "github.com/moolen/aegis/internal/metrics"
	"github.com/moolen/aegis/internal/policy"
	"github.com/moolen/aegis/internal/policydiscovery"
	"github.com/moolen/aegis/internal/proxy"
)

type Options struct {
	ConfigPath string
	Logger     *slog.Logger
}

func Run(ctx context.Context, opts Options) error {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}

	cfg, err := loadRuntimeConfig(opts.ConfigPath)
	if err != nil {
		logger.Error("load config failed", "path", opts.ConfigPath, "error", err)
		return err
	}

	registry := prometheus.NewRegistry()
	metrics := appmetrics.New(registry)
	drainTracker := proxy.NewDrainTracker(logger, metrics)
	reloadableHandler := &reloadableProxyHandler{}
	manager := newRuntimeManager(ctx, logger, metrics, opts.ConfigPath, reloadableHandler, drainTracker)
	defer manager.Close()
	if err := manager.LoadInitial(cfg); err != nil {
		logger.Error("build runtime failed", "error", err)
		return err
	}

	metricsHandler := appmetrics.NewServer(cfg.Metrics.Listen, registry, manager, nil).Handler()
	var adminHandler http.Handler
	if cfg.Admin.Enabled {
		adminHandler = appmetrics.NewAdminServer(cfg.Admin.Listen, manager).Handler()
	}
	var pprofHandler http.Handler
	if cfg.Pprof.Enabled {
		pprofHandler = appmetrics.NewPprofServer(cfg.Pprof.Listen).Handler()
	}

	proxySrv, metricsSrv, adminSrv, pprofSrv := newHTTPServers(cfg, reloadableHandler, metricsHandler, adminHandler, pprofHandler)
	proxyListener, metricsListener, adminListener, pprofListener, err := buildListeners(cfg, logger, metrics)
	if err != nil {
		logger.Error("build listeners failed", "error", err)
		return err
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
				return err
			}
			return nil
		case <-reloadCh:
			if err := manager.ReloadFromFile(); err != nil {
				logger.Error("reload config failed", "path", opts.ConfigPath, "error", err)
				continue
			}
			logger.Info("config reloaded", "path", opts.ConfigPath)
		case <-ctx.Done():
			logger.Info("shutdown signal received")
			goto shutdown
		}
	}

shutdown:
	shutdownCtx, cancel := context.WithTimeout(context.Background(), manager.ShutdownGracePeriod())
	defer cancel()

	if err := shutdownHTTPServer(logger, "proxy", proxySrv, shutdownCtx); err != nil {
		return err
	}
	if err := shutdownHTTPServer(logger, "metrics", metricsSrv, shutdownCtx); err != nil {
		return err
	}
	if adminSrv != nil {
		if err := shutdownHTTPServer(logger, "admin", adminSrv, shutdownCtx); err != nil {
			return err
		}
	}
	if pprofSrv != nil {
		if err := shutdownHTTPServer(logger, "pprof", pprofSrv, shutdownCtx); err != nil {
			return err
		}
	}

	drainResult := drainTracker.Shutdown(shutdownCtx)
	logger.Info("aegis shutdown complete", "result", drainResult, "grace_period", manager.ShutdownGracePeriod())
	logger.Info("aegis stopped")
	return nil
}

type reloadableProxyHandler struct {
	current atomic.Value
}

type policyDiscoveryRunner interface {
	Start() error
	Close() error
}

type policyDiscoveryApplyFunc func(sourceName string, snapshot policydiscovery.Snapshot) error

var newPolicyDiscoveryRunner = func(ctx context.Context, logger *slog.Logger, metrics *appmetrics.Metrics, sources []config.PolicyDiscoverySourceConfig, apply policyDiscoveryApplyFunc) (policyDiscoveryRunner, error) {
	return policydiscovery.NewRunner(ctx, logger, metrics, sources, policydiscovery.ApplyFunc(apply))
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
	rootCtx     context.Context
	logger      *slog.Logger
	metrics     *appmetrics.Metrics
	configPath  string
	handler     *reloadableProxyHandler
	drain       *proxy.DrainTracker
	limiter     *proxy.ConnectionLimiter
	enforcement *proxy.EnforcementOverrideController

	mu               sync.RWMutex
	current          runtimeGeneration
	nextGenerationID uint64
	closed           bool
}

type runtimeGeneration struct {
	id               uint64
	cfg              config.Config
	cancel           context.CancelFunc
	mitm             *proxy.MITMEngine
	upstreamHTTP     *http.Transport
	readyChecker     appmetrics.ReadyChecker
	identityResolver proxy.IdentityResolver
	policyEngine     proxy.PolicyEngine
	policyRuntime    *runtimePolicyEngine
	policyDiscovery  *runtimePolicyDiscovery
}

var errRuntimeManagerClosed = errors.New("runtime manager closed")

func newRuntimeManager(rootCtx context.Context, logger *slog.Logger, metrics *appmetrics.Metrics, configPath string, handler *reloadableProxyHandler, drain *proxy.DrainTracker) *runtimeManager {
	if drain == nil {
		drain = proxy.NewDrainTracker(logger, metrics)
	}
	return &runtimeManager{
		rootCtx:     rootCtx,
		logger:      logger,
		metrics:     metrics,
		configPath:  configPath,
		handler:     handler,
		drain:       drain,
		limiter:     proxy.NewConnectionLimiter(logger, metrics),
		enforcement: proxy.NewEnforcementOverrideController(logger),
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
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.closed = true
	m.nextGenerationID++
	current := m.current
	m.current = runtimeGeneration{}
	m.mu.Unlock()

	logRuntimeGenerationCloseError(m.logger, "close active generation", closeRuntimeGeneration(current))
	policydiscovery.DeleteSourceMetrics(m.metrics, current.cfg.Discovery.Policies)
}

func (m *runtimeManager) applyConfig(cfg config.Config, enforceImmutable bool) error {
	if err := validateRuntimeConfig(cfg); err != nil {
		return err
	}

	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return errRuntimeManagerClosed
	}
	if enforceImmutable {
		if err := validateReloadableConfig(m.current.cfg, cfg); err != nil {
			m.mu.Unlock()
			return err
		}
	}
	m.nextGenerationID++
	generationID := m.nextGenerationID
	m.mu.Unlock()

	generationCtx, cancel := context.WithCancel(m.rootCtx)
	deps, err := buildProxyDependencies(generationCtx, cfg, m.logger, m.metrics, m.drain, m.limiter, m.enforcement)
	if err != nil {
		cancel()
		return err
	}
	frozenGenerationID, carriedSnapshots, err := m.freezeRemotePolicyStateForReload(generationID, cfg.Discovery.Policies)
	if err != nil {
		cancel()
		if deps.UpstreamHTTPTransport != nil {
			deps.UpstreamHTTPTransport.CloseIdleConnections()
		}
		return err
	}
	releaseFrozen := true
	defer func() {
		if releaseFrozen {
			m.unfreezeRemotePolicyState(frozenGenerationID)
		}
	}()

	m.limiter.UpdateLimit(cfg.Proxy.ConnectionLimits.MaxConcurrentPerIdentity)

	nextGeneration := runtimeGeneration{
		id:               generationID,
		cfg:              cfg,
		cancel:           cancel,
		mitm:             deps.MITM,
		upstreamHTTP:     deps.UpstreamHTTPTransport,
		identityResolver: deps.IdentityResolver,
	}
	if err := prepareRuntimePolicyDiscovery(generationCtx, m.logger, m.metrics, &nextGeneration, carriedSnapshots); err != nil {
		logRuntimeGenerationCloseError(m.logger, "close failed next generation", closeRuntimeGeneration(nextGeneration))
		return err
	}
	deps.PolicyEngine = nextGeneration.policyRuntime

	nextHandler := newProxyServer(deps).Handler()
	if checker, ok := deps.IdentityResolver.(appmetrics.ReadyChecker); ok {
		nextGeneration.readyChecker = checker
	}

	if err := startRuntimePolicyDiscovery(nextGeneration.policyDiscovery); err != nil {
		logRuntimeGenerationCloseError(m.logger, "close failed next generation after discovery start error", closeRuntimeGeneration(nextGeneration))
		return err
	}

	m.mu.Lock()
	if m.closed || generationID != m.nextGenerationID {
		m.mu.Unlock()
		logRuntimeGenerationCloseError(m.logger, "close canceled next generation", closeRuntimeGeneration(nextGeneration))
		return context.Canceled
	}
	previous := m.current
	m.handler.Swap(nextHandler)
	m.recordMITMLifecycle(previous.mitm, deps.MITM, enforceImmutable)
	m.current = nextGeneration
	m.mu.Unlock()
	releaseFrozen = false

	logRuntimeGenerationCloseError(m.logger, "retire previous generation", closeRuntimeGeneration(previous))
	cleanupRemovedPolicyDiscoverySourceMetrics(m.metrics, previous.policyDiscovery, nextGeneration.policyDiscovery)
	m.recordEnforcementStatus()

	return nil
}

func (m *runtimeManager) freezeRemotePolicyStateForReload(generationID uint64, nextSources []config.PolicyDiscoverySourceConfig) (uint64, map[string]policydiscovery.Snapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed || generationID != m.nextGenerationID {
		return 0, nil, context.Canceled
	}

	if m.current.id == 0 {
		return 0, make(map[string]policydiscovery.Snapshot), nil
	}

	if m.current.policyDiscovery == nil {
		return m.current.id, make(map[string]policydiscovery.Snapshot), nil
	}

	freezeRuntimePolicyDiscovery(m.current.policyDiscovery)
	return m.current.id, carryForwardRuntimePolicySnapshots(m.current.policyDiscovery, nextSources), nil
}

func (m *runtimeManager) unfreezeRemotePolicyState(generationID uint64) {
	if generationID == 0 {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed || m.current.id != generationID {
		return
	}

	if m.current.policyDiscovery == nil {
		return
	}
	unfreezeRuntimePolicyDiscovery(m.current.policyDiscovery)
}

func (m *runtimeManager) ShutdownGracePeriod() time.Duration {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.current.cfg.Shutdown.GracePeriod <= 0 {
		return 10 * time.Second
	}
	return m.current.cfg.Shutdown.GracePeriod
}

func (m *runtimeManager) CheckReadiness() error {
	m.mu.RLock()
	checker := m.current.readyChecker
	m.mu.RUnlock()

	if checker == nil {
		return nil
	}
	return checker.CheckReadiness()
}

func (m *runtimeManager) AdminToken() string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if !m.current.cfg.Admin.Enabled {
		return ""
	}
	return m.current.cfg.Admin.Token
}

func (m *runtimeManager) EnforcementStatus() appmetrics.EnforcementStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return enforcementStatusForConfig(m.current.cfg, m.enforcement)
}

func (m *runtimeManager) RuntimeStatus() appmetrics.RuntimeStatus {
	m.mu.RLock()
	mitm := m.current.mitm
	m.mu.RUnlock()

	if mitm == nil {
		return appmetrics.RuntimeStatus{}
	}

	status := mitm.CAStatus()
	return appmetrics.RuntimeStatus{
		MITM: &appmetrics.MITMStatus{
			Enabled:               true,
			IssuerFingerprint:     status.IssuerFingerprint,
			CompanionFingerprints: status.CompanionFingerprints,
			AllFingerprints:       status.AllFingerprints,
		},
	}
}

func (m *runtimeManager) SetEnforcementMode(mode string) (appmetrics.EnforcementStatus, error) {
	normalized := config.NormalizeEnforcementMode(mode)
	switch normalized {
	case "config":
		m.enforcement.ClearOverride()
	case config.EnforcementAudit, config.EnforcementEnforce:
		if err := m.enforcement.SetOverride(normalized); err != nil {
			return appmetrics.EnforcementStatus{}, err
		}
	default:
		return appmetrics.EnforcementStatus{}, fmt.Errorf("mode must be audit, enforce, or config")
	}

	status := m.EnforcementStatus()
	m.recordEnforcementStatus()
	m.logger.Warn("global enforcement mode changed", "configured_mode", status.Configured, "override_mode", normalizeOverrideMode(status.Override), "effective_mode", status.Effective)
	return status, nil
}

func (m *runtimeManager) Reload() error {
	return m.ReloadFromFile()
}

func (m *runtimeManager) DumpIdentities() []appmetrics.IdentityDumpRecord {
	m.mu.RLock()
	resolver := m.current.identityResolver
	m.mu.RUnlock()

	dumper, ok := resolver.(interface{ IdentityDump() []identity.DumpEntry })
	if !ok {
		return nil
	}

	entries := dumper.IdentityDump()
	out := make([]appmetrics.IdentityDumpRecord, 0, len(entries))
	for _, entry := range entries {
		record := appmetrics.IdentityDumpRecord{
			IP:        entry.IP,
			Effective: identityRecordFromMapping(entry.Effective),
		}
		for _, shadow := range entry.Shadows {
			record.Shadows = append(record.Shadows, *identityRecordFromMapping(&shadow))
		}
		out = append(out, record)
	}
	return out
}

func (m *runtimeManager) Simulate(req appmetrics.SimulationRequest) (appmetrics.SimulationResponse, error) {
	sourceAddr, err := netip.ParseAddr(req.SourceIP)
	if err != nil {
		return appmetrics.SimulationResponse{}, fmt.Errorf("sourceIP must be a valid IP address")
	}
	sourceAddr = sourceAddr.Unmap()
	sourceIP := net.IP(sourceAddr.AsSlice())

	m.mu.RLock()
	generation := m.current
	status := enforcementStatusForConfig(generation.cfg, m.enforcement)
	m.mu.RUnlock()

	resp := appmetrics.SimulationResponse{
		UnknownIdentityPolicy: config.NormalizeUnknownIdentityPolicy(generation.cfg.Proxy.UnknownIdentityPolicy),
		ConfiguredMode:        status.Configured,
		OverrideMode:          status.Override,
		EffectiveMode:         status.Effective,
		Protocol:              req.Protocol,
		FQDN:                  req.FQDN,
		Port:                  req.Port,
		Method:                req.Method,
		Path:                  req.Path,
	}

	id := identity.Unknown()
	if generation.identityResolver != nil {
		resolved, err := generation.identityResolver.Resolve(sourceIP)
		if err != nil {
			if m.logger != nil {
				m.logger.Debug("resolve simulated source identity failed", "source_ip", sourceIP.String(), "error", err)
			}
		} else if resolved != nil {
			id = resolved
		}
	}
	resp.Identity = identityRecordFromIdentity(id, id.Provider, id.Source)
	resp.UnknownIdentity = isUnknownIdentity(id)

	var outcome policy.Outcome
	policyInput := policy.EvaluateInput{
		Identity:              id,
		SourceIP:              sourceAddr,
		FQDN:                  req.FQDN,
		Port:                  req.Port,
		Method:                req.Method,
		Path:                  req.Path,
		EnforcementMode:       status.Effective,
		UnknownIdentityPolicy: resp.UnknownIdentityPolicy,
	}
	switch req.Protocol {
	case "connect":
		outcome = policy.EvaluateConnectOutcome(generation.policyEngine, policyInput)
	case "http", "":
		outcome = policy.EvaluateHTTPOutcome(generation.policyEngine, policyInput)
	default:
		return appmetrics.SimulationResponse{}, fmt.Errorf("protocol must be http or connect")
	}
	if outcome.Policy != "" || outcome.Rule != "" || outcome.RequestedTLSMode != "" || outcome.PolicyBypass || outcome.PolicyEnforcement != "" || outcome.Reason != "" {
		resp.Decision = &appmetrics.SimulationDecision{
			Allowed:           outcome.Allowed,
			Policy:            outcome.Policy,
			Rule:              outcome.Rule,
			TLSMode:           outcome.RequestedTLSMode,
			Bypass:            outcome.PolicyBypass,
			PolicyEnforcement: outcome.PolicyEnforcement,
		}
	}

	resp.Action = outcome.Action
	resp.Reason = outcome.Reason
	resp.WouldAction = outcome.Audit.WouldAction
	resp.WouldReason = outcome.Audit.WouldReason
	resp.WouldBlock = outcome.Audit.WouldBlock
	return resp, nil
}

func (m *runtimeManager) recordReloadResult(result string) {
	if m.metrics == nil {
		return
	}
	m.metrics.ConfigReloadsTotal.WithLabelValues(result).Inc()
}

func (m *runtimeManager) recordEnforcementStatus() {
	if m.metrics == nil {
		return
	}

	status := m.EnforcementStatus()
	for _, mode := range []string{config.EnforcementEnforce, config.EnforcementAudit} {
		value := 0.0
		if status.Configured == mode {
			value = 1
		}
		m.metrics.EnforcementMode.WithLabelValues("configured", mode).Set(value)

		value = 0.0
		if status.Effective == mode {
			value = 1
		}
		m.metrics.EnforcementMode.WithLabelValues("effective", mode).Set(value)
	}
	for _, mode := range []string{"none", config.EnforcementEnforce, config.EnforcementAudit} {
		value := 0.0
		if normalizeOverrideMode(status.Override) == mode {
			value = 1
		}
		m.metrics.EnforcementMode.WithLabelValues("override", mode).Set(value)
	}
}

func (m *runtimeManager) recordMITMLifecycle(previous *proxy.MITMEngine, next *proxy.MITMEngine, isReload bool) {
	result := classifyMITMLifecycle(previous, next, isReload)
	if result == "" {
		return
	}

	if m.metrics != nil {
		m.metrics.MITMCACyclesTotal.WithLabelValues(result).Inc()
	}

	switch result {
	case "initial":
		m.logger.Info("mitm ca loaded", "fingerprints", next.Fingerprints())
	case "enabled":
		m.logger.Info("mitm ca enabled", "fingerprints", next.Fingerprints())
	case "disabled":
		m.logger.Info("mitm ca disabled")
	case "unchanged":
		m.logger.Info("mitm ca reloaded without fingerprint change", "fingerprints", next.Fingerprints())
	case "companions_changed":
		previousStatus := previous.CAStatus()
		nextStatus := next.CAStatus()
		m.logger.Info(
			"mitm ca companions changed",
			"previous_issuer_fingerprint", previousStatus.IssuerFingerprint,
			"issuer_fingerprint", nextStatus.IssuerFingerprint,
			"previous_companion_fingerprints", previousStatus.CompanionFingerprints,
			"companion_fingerprints", nextStatus.CompanionFingerprints,
		)
	case "rotated":
		previousStatus := previous.CAStatus()
		nextStatus := next.CAStatus()
		m.logger.Info(
			"mitm ca rotated",
			"previous_issuer_fingerprint", previousStatus.IssuerFingerprint,
			"issuer_fingerprint", nextStatus.IssuerFingerprint,
			"previous_companion_fingerprints", previousStatus.CompanionFingerprints,
			"companion_fingerprints", nextStatus.CompanionFingerprints,
			"previous_fingerprints", previousStatus.AllFingerprints,
			"fingerprints", nextStatus.AllFingerprints,
		)
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
	if current.Pprof.Enabled != next.Pprof.Enabled {
		return fmt.Errorf("pprof.enabled cannot change during reload")
	}
	if current.Pprof.Listen != next.Pprof.Listen {
		return fmt.Errorf("pprof.listen cannot change during reload")
	}
	if current.Admin.Enabled != next.Admin.Enabled {
		return fmt.Errorf("admin.enabled cannot change during reload")
	}
	if current.Admin.Listen != next.Admin.Listen {
		return fmt.Errorf("admin.listen cannot change during reload")
	}
	if current.Proxy.ProxyProtocol.Enabled != next.Proxy.ProxyProtocol.Enabled {
		return fmt.Errorf("proxy.proxyProtocol.enabled cannot change during reload")
	}
	if proxyProtocolTimeoutForConfig(current.Proxy.ProxyProtocol) != proxyProtocolTimeoutForConfig(next.Proxy.ProxyProtocol) {
		return fmt.Errorf("proxy.proxyProtocol.headerTimeout cannot change during reload")
	}
	if !slices.Equal(proxyProtocolTrustedCIDRsForConfig(current.Proxy.ProxyProtocol), proxyProtocolTrustedCIDRsForConfig(next.Proxy.ProxyProtocol)) {
		return fmt.Errorf("proxy.proxyProtocol.trustedCIDRs cannot change during reload")
	}
	return nil
}

func proxyProtocolTimeoutForConfig(cfg config.ProxyProtocolConfig) int64 {
	if cfg.HeaderTimeout == nil {
		return proxyProtocolHeaderTimeout.Nanoseconds()
	}
	return cfg.HeaderTimeout.Nanoseconds()
}

type runtimePolicyEngine struct {
	mu      sync.RWMutex
	current proxy.PolicyEngine
}

func newRuntimePolicyEngine(initial proxy.PolicyEngine) *runtimePolicyEngine {
	return &runtimePolicyEngine{current: initial}
}

func (e *runtimePolicyEngine) Update(next proxy.PolicyEngine) {
	e.mu.Lock()
	e.current = next
	e.mu.Unlock()
}

func (e *runtimePolicyEngine) Evaluate(id *identity.Identity, sourceIP netip.Addr, fqdn string, port int, method string, path string) *policy.Decision {
	e.mu.RLock()
	current := e.current
	e.mu.RUnlock()
	if current == nil {
		return nil
	}
	return current.Evaluate(id, sourceIP, fqdn, port, method, path)
}

func (e *runtimePolicyEngine) EvaluateConnect(id *identity.Identity, sourceIP netip.Addr, fqdn string, port int) *policy.Decision {
	e.mu.RLock()
	current := e.current
	e.mu.RUnlock()
	if current == nil {
		return nil
	}
	return current.EvaluateConnect(id, sourceIP, fqdn, port)
}

func closeRuntimeGeneration(generation runtimeGeneration) error {
	var err error
	if generation.cancel != nil {
		generation.cancel()
	}
	err = errors.Join(err, closeRuntimePolicyDiscovery(generation.policyDiscovery))
	if generation.upstreamHTTP != nil {
		generation.upstreamHTTP.CloseIdleConnections()
	}
	return err
}

func logRuntimeGenerationCloseError(logger *slog.Logger, stage string, err error) {
	if err == nil || logger == nil {
		return
	}
	logger.Error("runtime generation cleanup failed", "stage", stage, "error", err)
}

type noopPolicyDiscoveryRunner struct{}

func (noopPolicyDiscoveryRunner) Start() error {
	return nil
}

func (noopPolicyDiscoveryRunner) Close() error {
	return nil
}

func proxyProtocolTrustedCIDRsForConfig(cfg config.ProxyProtocolConfig) []string {
	if len(cfg.TrustedCIDRs) == 0 {
		return nil
	}
	out := make([]string, 0, len(cfg.TrustedCIDRs))
	for _, value := range cfg.TrustedCIDRs {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			out = append(out, value)
			continue
		}
		out = append(out, prefix.String())
	}
	slices.Sort(out)
	return out
}

func enforcementStatusForConfig(cfg config.Config, controller *proxy.EnforcementOverrideController) appmetrics.EnforcementStatus {
	configured := config.NormalizeEnforcementMode(cfg.Proxy.Enforcement)
	status := appmetrics.EnforcementStatus{
		Configured: configured,
		Effective:  proxy.EffectiveEnforcementMode(configured, controller),
	}
	if override, ok := controller.OverrideMode(); ok {
		status.Override = override
	}
	return status
}

func normalizeOverrideMode(mode string) string {
	if mode == "" {
		return "none"
	}
	return mode
}

func identityRecordFromMapping(mapping *identity.Mapping) *appmetrics.IdentityRecord {
	if mapping == nil {
		return nil
	}
	return identityRecordFromIdentity(mapping.Identity, mapping.Provider, mapping.Kind)
}

func identityRecordFromIdentity(id *identity.Identity, provider string, kind string) *appmetrics.IdentityRecord {
	if id == nil {
		return nil
	}
	labels := make(map[string]string, len(id.Labels))
	for key, value := range id.Labels {
		labels[key] = value
	}
	return &appmetrics.IdentityRecord{
		Source:   firstNonEmpty(kind, id.Source),
		Provider: firstNonEmpty(provider, id.Provider),
		Kind:     firstNonEmpty(kind, id.Source),
		Name:     id.Name,
		Labels:   labels,
	}
}

func isUnknownIdentity(id *identity.Identity) bool {
	return id == nil || id.Source == "unknown" || id.Name == identity.Unknown().Name
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func sameMITMCASet(left *proxy.MITMEngine, right *proxy.MITMEngine) bool {
	return sameMITMCAStatus(left.CAStatus(), right.CAStatus())
}

func classifyMITMLifecycle(previous *proxy.MITMEngine, next *proxy.MITMEngine, isReload bool) string {
	switch {
	case previous == nil && next == nil:
		return ""
	case previous == nil && next != nil:
		if isReload {
			return "enabled"
		}
		return "initial"
	case previous != nil && next == nil:
		return "disabled"
	case sameMITMCASet(previous, next):
		return "unchanged"
	case previous.CAStatus().IssuerFingerprint != next.CAStatus().IssuerFingerprint:
		return "rotated"
	default:
		return "companions_changed"
	}
}

func sameMITMCAStatus(left proxy.MITMCAStatus, right proxy.MITMCAStatus) bool {
	if left.IssuerFingerprint != right.IssuerFingerprint {
		return false
	}
	return sameFingerprintSet(left.CompanionFingerprints, right.CompanionFingerprints)
}

func sameFingerprintSet(left []string, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
