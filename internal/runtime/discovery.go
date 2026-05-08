package runtime

import (
	"context"
	"log/slog"
	"strings"
	"sync"

	"github.com/moolen/aegis/internal/config"
	"github.com/moolen/aegis/internal/identity"
	appmetrics "github.com/moolen/aegis/internal/metrics"
	"github.com/moolen/aegis/internal/policydiscovery"
	"github.com/moolen/aegis/internal/proxy"
)

var newIdentityDiscoveryRuntime = func(cfg config.DiscoveryConfig, logger *slog.Logger, m *appmetrics.Metrics) interface {
	Start(context.Context) (proxy.IdentityResolver, error)
} {
	return identityDiscoveryRuntimeAdapter{runtime: identity.NewDiscoveryRuntime(cfg, logger, m)}
}

type runtimePolicyDiscovery struct {
	mu             sync.RWMutex
	staticPolicies []config.PolicyConfig
	sources        []config.PolicyDiscoverySourceConfig
	snapshots      map[string]policydiscovery.Snapshot
	mergedPolicies []config.PolicyConfig
	policyRuntime  *runtimePolicyEngine
	runner         policyDiscoveryRunner
	frozen         bool
	closed         bool
}

func buildIdentityResolver(ctx context.Context, cfg config.DiscoveryConfig, logger *slog.Logger, m *appmetrics.Metrics) (proxy.IdentityResolver, error) {
	resolver, err := newIdentityDiscoveryRuntime(cfg, logger, m).Start(ctx)
	if err != nil {
		return nil, err
	}
	return resolver, nil
}

type identityDiscoveryRuntimeAdapter struct {
	runtime *identity.DiscoveryRuntime
}

func (a identityDiscoveryRuntimeAdapter) Start(ctx context.Context) (proxy.IdentityResolver, error) {
	if a.runtime == nil {
		return nil, nil
	}
	resolver, err := a.runtime.Start(ctx)
	if err != nil {
		return nil, err
	}
	if resolver == nil {
		return nil, nil
	}
	return resolver, nil
}

func prepareRuntimePolicyDiscovery(ctx context.Context, logger *slog.Logger, metrics *appmetrics.Metrics, generation *runtimeGeneration, carriedSnapshots map[string]policydiscovery.Snapshot) error {
	engine, mergedPolicies, err := policydiscovery.CompileMergedEngine(generation.cfg.Policies, carriedSnapshots)
	if err != nil {
		return err
	}

	policyRuntime := newRuntimePolicyEngine(engine)
	discovery := &runtimePolicyDiscovery{
		staticPolicies: append([]config.PolicyConfig(nil), generation.cfg.Policies...),
		sources:        append([]config.PolicyDiscoverySourceConfig(nil), generation.cfg.Discovery.Policies...),
		snapshots:      cloneRuntimePolicySnapshots(carriedSnapshots),
		mergedPolicies: mergedPolicies,
		policyRuntime:  policyRuntime,
	}
	if len(discovery.sources) != 0 {
		runner, err := newPolicyDiscoveryRunner(ctx, logger, metrics, discovery.sources, discovery.applySnapshot)
		if err != nil {
			return err
		}
		discovery.runner = runner
	}

	generation.policyRuntime = policyRuntime
	generation.policyEngine = policyRuntime
	generation.policyDiscovery = discovery
	return nil
}

func startRuntimePolicyDiscovery(discovery *runtimePolicyDiscovery) error {
	if discovery == nil || discovery.runner == nil {
		return nil
	}
	return discovery.runner.Start()
}

func closeRuntimePolicyDiscovery(discovery *runtimePolicyDiscovery) error {
	if discovery == nil {
		return nil
	}

	discovery.mu.Lock()
	if discovery.closed {
		discovery.mu.Unlock()
		return nil
	}
	discovery.closed = true
	runner := discovery.runner
	discovery.mu.Unlock()

	if runner == nil {
		return nil
	}
	return runner.Close()
}

func freezeRuntimePolicyDiscovery(discovery *runtimePolicyDiscovery) {
	if discovery == nil {
		return
	}
	discovery.mu.Lock()
	discovery.frozen = true
	discovery.mu.Unlock()
}

func unfreezeRuntimePolicyDiscovery(discovery *runtimePolicyDiscovery) {
	if discovery == nil {
		return
	}
	discovery.mu.Lock()
	if !discovery.closed {
		discovery.frozen = false
	}
	discovery.mu.Unlock()
}

func carryForwardRuntimePolicySnapshots(discovery *runtimePolicyDiscovery, nextSources []config.PolicyDiscoverySourceConfig) map[string]policydiscovery.Snapshot {
	if discovery == nil {
		return make(map[string]policydiscovery.Snapshot)
	}

	discovery.mu.RLock()
	defer discovery.mu.RUnlock()

	return carryForwardPolicySnapshots(discovery.snapshots, discovery.sources, nextSources)
}

func cleanupRemovedPolicyDiscoverySourceMetrics(metrics *appmetrics.Metrics, previous *runtimePolicyDiscovery, next *runtimePolicyDiscovery) {
	policydiscovery.DeleteSourceMetrics(metrics, removedPolicyDiscoverySources(policyDiscoverySources(previous), policyDiscoverySources(next)))
}

func policyDiscoverySources(discovery *runtimePolicyDiscovery) []config.PolicyDiscoverySourceConfig {
	if discovery == nil {
		return nil
	}
	discovery.mu.RLock()
	defer discovery.mu.RUnlock()

	return append([]config.PolicyDiscoverySourceConfig(nil), discovery.sources...)
}

func (d *runtimePolicyDiscovery) applySnapshot(sourceName string, snapshot policydiscovery.Snapshot) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed || d.frozen {
		return context.Canceled
	}

	nextSnapshots := policydiscovery.ReplaceSourceSnapshot(d.snapshots, sourceName, snapshot)
	engine, mergedPolicies, err := policydiscovery.CompileMergedEngine(d.staticPolicies, nextSnapshots)
	if err != nil {
		return err
	}

	d.policyRuntime.Update(engine)
	d.snapshots = nextSnapshots
	d.mergedPolicies = mergedPolicies
	return nil
}

func (g runtimeGeneration) mergedPolicyConfigs() []config.PolicyConfig {
	if g.policyDiscovery == nil {
		return nil
	}
	g.policyDiscovery.mu.RLock()
	defer g.policyDiscovery.mu.RUnlock()

	return append([]config.PolicyConfig(nil), g.policyDiscovery.mergedPolicies...)
}

func (g runtimeGeneration) remotePolicySnapshots() map[string]policydiscovery.Snapshot {
	if g.policyDiscovery == nil {
		return make(map[string]policydiscovery.Snapshot)
	}
	g.policyDiscovery.mu.RLock()
	defer g.policyDiscovery.mu.RUnlock()

	return cloneRuntimePolicySnapshots(g.policyDiscovery.snapshots)
}

func (g runtimeGeneration) activePolicyDiscoveryRunner() policyDiscoveryRunner {
	if g.policyDiscovery == nil {
		return nil
	}
	g.policyDiscovery.mu.RLock()
	defer g.policyDiscovery.mu.RUnlock()

	return g.policyDiscovery.runner
}

func cloneRuntimePolicySnapshots(current map[string]policydiscovery.Snapshot) map[string]policydiscovery.Snapshot {
	if len(current) == 0 {
		return make(map[string]policydiscovery.Snapshot)
	}

	cloned := make(map[string]policydiscovery.Snapshot, len(current))
	for sourceName, snapshot := range current {
		cloned[sourceName] = snapshot
	}
	return cloned
}

func carryForwardPolicySnapshots(current map[string]policydiscovery.Snapshot, previousSources []config.PolicyDiscoverySourceConfig, nextSources []config.PolicyDiscoverySourceConfig) map[string]policydiscovery.Snapshot {
	if len(current) == 0 || len(nextSources) == 0 {
		return make(map[string]policydiscovery.Snapshot)
	}
	allowed := make(map[string]struct{}, len(nextSources))
	for _, source := range nextSources {
		allowed[policyDiscoverySourceIdentity(source)] = struct{}{}
	}
	previousByName := make(map[string]config.PolicyDiscoverySourceConfig, len(previousSources))
	for _, source := range previousSources {
		previousByName[strings.TrimSpace(source.Name)] = source
	}
	carried := make(map[string]policydiscovery.Snapshot, len(current))
	for sourceName, snapshot := range current {
		sourceCfg, ok := previousByName[strings.TrimSpace(sourceName)]
		if !ok {
			sourceCfg = snapshot.Source
		}
		if _, ok := allowed[policyDiscoverySourceIdentity(sourceCfg)]; ok {
			carried[sourceName] = snapshot
		}
	}
	return carried
}

func removedPolicyDiscoverySources(previous []config.PolicyDiscoverySourceConfig, next []config.PolicyDiscoverySourceConfig) []config.PolicyDiscoverySourceConfig {
	if len(previous) == 0 {
		return nil
	}
	nextByIdentity := make(map[string]struct{}, len(next))
	for _, source := range next {
		nextByIdentity[policyDiscoverySourceIdentity(source)] = struct{}{}
	}
	removed := make([]config.PolicyDiscoverySourceConfig, 0, len(previous))
	for _, source := range previous {
		if _, ok := nextByIdentity[policyDiscoverySourceIdentity(source)]; ok {
			continue
		}
		removed = append(removed, source)
	}
	return removed
}

func policyDiscoverySourceIdentity(source config.PolicyDiscoverySourceConfig) string {
	return strings.TrimSpace(source.Name) + "\x00" +
		strings.ToLower(strings.TrimSpace(source.Provider)) + "\x00" +
		strings.TrimSpace(source.Bucket) + "\x00" +
		strings.TrimSpace(source.Prefix) + "\x00" +
		strings.ToLower(strings.TrimSpace(source.Auth.Mode))
}
