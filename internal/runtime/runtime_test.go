package runtime

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/moolen/aegis/internal/config"
	"github.com/moolen/aegis/internal/identity"
	appmetrics "github.com/moolen/aegis/internal/metrics"
	"github.com/moolen/aegis/internal/policydiscovery"
	"github.com/moolen/aegis/internal/proxy"
)

func TestRunFailsWhenInitialConfigLoadFails(t *testing.T) {
	err := Run(context.Background(), Options{
		ConfigPath: t.TempDir() + "/missing.yaml",
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err == nil {
		t.Fatal("expected Run() to fail")
	}
	if !strings.Contains(err.Error(), "load config") {
		t.Fatalf("Run() error = %q, want load config failure", err)
	}
}

func TestRunStartsAndStopsOnContextCancel(t *testing.T) {
	stubRuntimeKubernetesProvider(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	configPath := writeRuntimeConfig(t, runtimeConfigYAML("policy-a", "127.0.0.1:0", "127.0.0.2:0", false, ""))
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Options{
			ConfigPath: configPath,
			Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		})
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run() error = %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run() did not stop after context cancellation")
	}
}

func TestRunShutdownUsesActiveGenerationGracePeriod(t *testing.T) {
	stubRuntimeKubernetesProvider(t)
	restoreShutdown := shutdownHTTPServer
	t.Cleanup(func() {
		shutdownHTTPServer = restoreShutdown
	})

	var shutdownCalls int
	var firstRemaining time.Duration
	shutdownHTTPServer = func(logger *slog.Logger, name string, srv *http.Server, ctx context.Context) error {
		shutdownCalls++
		deadline, ok := ctx.Deadline()
		if !ok {
			t.Fatal("shutdown context missing deadline")
		}
		if firstRemaining == 0 {
			firstRemaining = time.Until(deadline)
		}
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	configPath := writeRuntimeConfig(t, runtimeConfigYAMLWithShutdownGrace("policy-a", "127.0.0.1:0", "127.0.0.2:0", 250*time.Millisecond))
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Options{
			ConfigPath: configPath,
			Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		})
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run() error = %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run() did not stop after context cancellation")
	}

	if shutdownCalls < 2 {
		t.Fatalf("shutdown calls = %d, want at least proxy and metrics", shutdownCalls)
	}
	if firstRemaining < 150*time.Millisecond || firstRemaining > 350*time.Millisecond {
		t.Fatalf("shutdown grace remaining = %s, want about 250ms", firstRemaining)
	}
}

func TestManagerReloadSwapsHandlerAndCountsSuccess(t *testing.T) {
	stubRuntimeKubernetesProvider(t)
	restoreProxyServer := newProxyServer
	t.Cleanup(func() {
		newProxyServer = restoreProxyServer
	})

	generation := 0
	newProxyServer = func(deps proxy.Dependencies) interface{ Handler() http.Handler } {
		generation++
		body := "generation-1"
		if generation == 2 {
			body = "generation-2"
		}
		return fakeHandlerProvider{handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, body)
		})}
	}

	configPath := writeRuntimeConfig(t, runtimeConfigYAML("policy-a", ":3128", ":9090", false, ""))
	reg := prometheus.NewRegistry()
	m := appmetrics.New(reg)
	handler := &reloadableProxyHandler{}
	manager := newRuntimeManager(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), m, configPath, handler, nil)
	defer manager.Close()

	cfg, err := loadRuntimeConfig(configPath)
	if err != nil {
		t.Fatalf("loadRuntimeConfig() error = %v", err)
	}
	if err := manager.LoadInitial(cfg); err != nil {
		t.Fatalf("LoadInitial() error = %v", err)
	}

	if got := serveReloadableHandler(t, handler); got != "generation-1" {
		t.Fatalf("body = %q, want generation-1", got)
	}

	writeRuntimeConfigAt(t, configPath, runtimeConfigYAML("policy-b", ":3128", ":9090", false, ""))
	if err := manager.ReloadFromFile(); err != nil {
		t.Fatalf("ReloadFromFile() error = %v", err)
	}

	if got := serveReloadableHandler(t, handler); got != "generation-2" {
		t.Fatalf("body = %q, want generation-2", got)
	}
	if got := counterValue(t, reg, "aegis_config_reloads_total", map[string]string{"result": "success"}); got != 1 {
		t.Fatalf("reload success metric = %v, want 1", got)
	}
}

func TestManagerReloadFailureKeepsCurrentHandlerAndCountsError(t *testing.T) {
	stubRuntimeKubernetesProvider(t)
	restoreProxyServer := newProxyServer
	t.Cleanup(func() {
		newProxyServer = restoreProxyServer
	})

	newProxyServer = func(deps proxy.Dependencies) interface{ Handler() http.Handler } {
		return fakeHandlerProvider{handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, "stable-generation")
		})}
	}

	configPath := writeRuntimeConfig(t, runtimeConfigYAML("policy-a", ":3128", ":9090", false, ""))
	reg := prometheus.NewRegistry()
	m := appmetrics.New(reg)
	handler := &reloadableProxyHandler{}
	manager := newRuntimeManager(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), m, configPath, handler, nil)
	defer manager.Close()

	cfg, err := loadRuntimeConfig(configPath)
	if err != nil {
		t.Fatalf("loadRuntimeConfig() error = %v", err)
	}
	if err := manager.LoadInitial(cfg); err != nil {
		t.Fatalf("LoadInitial() error = %v", err)
	}

	writeRuntimeConfigAt(t, configPath, runtimeConfigYAML("policy-b", ":4000", ":9090", false, ""))
	if err := manager.ReloadFromFile(); err == nil {
		t.Fatal("expected ReloadFromFile() to fail")
	}

	if got := serveReloadableHandler(t, handler); got != "stable-generation" {
		t.Fatalf("body = %q, want stable-generation", got)
	}
	if got := counterValue(t, reg, "aegis_config_reloads_total", map[string]string{"result": "error"}); got != 1 {
		t.Fatalf("reload error metric = %v, want 1", got)
	}
}

func TestManagerReloadRejectsImmutableListenerChanges(t *testing.T) {
	stubRuntimeKubernetesProvider(t)

	configPath := writeRuntimeConfig(t, runtimeConfigYAML("policy-a", "127.0.0.1:0", "127.0.0.2:0", false, ""))
	manager := newRuntimeManager(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), appmetrics.New(prometheus.NewRegistry()), configPath, &reloadableProxyHandler{}, nil)
	defer manager.Close()

	cfg, err := loadRuntimeConfig(configPath)
	if err != nil {
		t.Fatalf("loadRuntimeConfig() error = %v", err)
	}
	if err := manager.LoadInitial(cfg); err != nil {
		t.Fatalf("LoadInitial() error = %v", err)
	}

	writeRuntimeConfigAt(t, configPath, runtimeConfigYAML("policy-b", "127.0.0.1:0", "127.0.0.3:0", false, ""))
	err = manager.ReloadFromFile()
	if err == nil {
		t.Fatal("expected ReloadFromFile() to fail")
	}
	if got := err.Error(); got != "metrics.listen cannot change during reload" {
		t.Fatalf("ReloadFromFile() error = %q, want %q", got, "metrics.listen cannot change during reload")
	}
}

func TestManagerReloadRunnerStartFailureKeepsCurrentGenerationActive(t *testing.T) {
	stubRuntimeKubernetesProvider(t)
	restoreProxyServer := newProxyServer
	restorePolicyDiscoveryRunner := newPolicyDiscoveryRunner
	t.Cleanup(func() {
		newProxyServer = restoreProxyServer
		newPolicyDiscoveryRunner = restorePolicyDiscoveryRunner
	})

	generation := 0
	newProxyServer = func(deps proxy.Dependencies) interface{ Handler() http.Handler } {
		generation++
		body := "generation-1"
		if generation == 2 {
			body = "generation-2"
		}
		return fakeHandlerProvider{handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, body)
		})}
	}

	initialRunner := &fakePolicyDiscoveryRunner{}
	failingRunner := &fakePolicyDiscoveryRunner{
		startFn: func(*fakePolicyDiscoveryRunner) error {
			return errors.New("runner start failed")
		},
	}
	runnerCalls := 0
	newPolicyDiscoveryRunner = func(ctx context.Context, logger *slog.Logger, metrics *appmetrics.Metrics, sources []config.PolicyDiscoverySourceConfig, apply policyDiscoveryApplyFunc) (policyDiscoveryRunner, error) {
		runnerCalls++
		var runner *fakePolicyDiscoveryRunner
		switch runnerCalls {
		case 1:
			runner = initialRunner
		case 2:
			runner = failingRunner
		default:
			t.Fatalf("unexpected policy discovery runner build %d", runnerCalls)
		}
		runner.apply = apply
		runner.sources = append([]config.PolicyDiscoverySourceConfig(nil), sources...)
		return runner, nil
	}

	reg := prometheus.NewRegistry()
	m := appmetrics.New(reg)
	handler := &reloadableProxyHandler{}
	manager := newRuntimeManager(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), m, "", handler, nil)
	defer manager.Close()

	cfg := testRuntimeConfig()
	cfg.Discovery.Policies = []config.PolicyDiscoverySourceConfig{
		testPolicyDiscoverySource("remote-a", "bucket-a", "policies/team-a"),
	}
	if err := manager.LoadInitial(cfg); err != nil {
		t.Fatalf("LoadInitial() error = %v", err)
	}

	m.PolicyDiscoveryObjectsActive.WithLabelValues("remote-a", "aws").Set(1)
	m.PolicyDiscoveryPoliciesActive.WithLabelValues("remote-a", "aws").Set(1)
	m.PolicyDiscoveryLastSuccess.WithLabelValues("remote-a", "aws").Set(1700000300)

	nextCfg := testRuntimeConfig()
	nextCfg.Discovery.Policies = []config.PolicyDiscoverySourceConfig{
		testPolicyDiscoverySource("remote-b", "bucket-b", "policies/team-b"),
	}
	err := manager.applyConfig(nextCfg, true)
	if err == nil {
		t.Fatal("expected applyConfig() to fail")
	}

	if got := serveReloadableHandler(t, handler); got != "generation-1" {
		t.Fatalf("body = %q, want generation-1", got)
	}
	if got := manager.current.cfg.Discovery.Policies[0].Name; got != "remote-a" {
		t.Fatalf("active discovery source = %q, want remote-a", got)
	}
	if got := manager.current.activePolicyDiscoveryRunner(); got != initialRunner {
		t.Fatalf("active policy discovery runner = %#v, want initial runner", got)
	}
	if initialRunner.closeCalls != 0 {
		t.Fatalf("initial runner close calls = %d, want 0", initialRunner.closeCalls)
	}
	if failingRunner.closeCalls != 1 {
		t.Fatalf("failing runner close calls = %d, want 1", failingRunner.closeCalls)
	}
	assertPolicyDiscoveryMetricPresent(t, reg, "aegis_policy_discovery_objects_active", "remote-a", "aws")
	assertPolicyDiscoveryMetricPresent(t, reg, "aegis_policy_discovery_policies_active", "remote-a", "aws")
	assertPolicyDiscoveryMetricPresent(t, reg, "aegis_policy_discovery_last_success_timestamp_seconds", "remote-a", "aws")
}

func TestManagerAppliesRemotePolicySnapshotUpdate(t *testing.T) {
	restorePolicyDiscoveryRunner := newPolicyDiscoveryRunner
	t.Cleanup(func() {
		newPolicyDiscoveryRunner = restorePolicyDiscoveryRunner
	})

	runner := &fakePolicyDiscoveryRunner{}
	newPolicyDiscoveryRunner = func(ctx context.Context, logger *slog.Logger, metrics *appmetrics.Metrics, sources []config.PolicyDiscoverySourceConfig, apply policyDiscoveryApplyFunc) (policyDiscoveryRunner, error) {
		runner.apply = apply
		runner.sources = append([]config.PolicyDiscoverySourceConfig(nil), sources...)
		return runner, nil
	}

	manager := newRuntimeManager(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), appmetrics.New(prometheus.NewRegistry()), "", &reloadableProxyHandler{}, nil)
	defer manager.Close()

	cfg := testRuntimeConfig()
	cfg.Discovery = config.DiscoveryConfig{
		Policies: []config.PolicyDiscoverySourceConfig{{
			Name:     "remote-a",
			Provider: "aws",
			Bucket:   "policies",
			Prefix:   "env/prod",
		}},
	}
	cfg.Policies = []config.PolicyConfig{
		testRuntimeCIDRPolicy("static-allow", "10.0.0.0/24", "static.example.com"),
	}

	if err := manager.LoadInitial(cfg); err != nil {
		t.Fatalf("LoadInitial() error = %v", err)
	}
	if runner.apply == nil {
		t.Fatal("expected policy discovery apply callback")
	}

	before, err := manager.Simulate(appmetrics.SimulationRequest{
		Protocol: "connect",
		SourceIP: "10.1.0.10",
		FQDN:     "remote.example.com",
		Port:     443,
	})
	if err != nil {
		t.Fatalf("Simulate() before update error = %v", err)
	}
	if before.Decision == nil || before.Decision.Policy != "" || before.Decision.Allowed {
		t.Fatalf("Simulate() decision before update = %#v, want empty deny result", before.Decision)
	}

	err = runner.apply("remote-a", policydiscovery.Snapshot{
		Source: config.PolicyDiscoverySourceConfig{Name: "remote-a"},
		Policies: []policydiscovery.DiscoveredPolicy{{
			SourceName: "remote-a",
			Object: policydiscovery.ObjectRef{
				Key:      "env/prod/remote.yaml",
				URI:      "s3://policies/env/prod/remote.yaml",
				Revision: "\"etag-1\"",
			},
			Policy: testRuntimeCIDRPolicy("remote-allow", "10.1.0.0/24", "remote.example.com"),
		}},
	})
	if err != nil {
		t.Fatalf("apply remote snapshot error = %v", err)
	}

	after, err := manager.Simulate(appmetrics.SimulationRequest{
		Protocol: "connect",
		SourceIP: "10.1.0.10",
		FQDN:     "remote.example.com",
		Port:     443,
	})
	if err != nil {
		t.Fatalf("Simulate() after update error = %v", err)
	}
	if after.Decision == nil || after.Decision.Policy != "remote-allow" || !after.Decision.Allowed {
		t.Fatalf("Simulate() decision after update = %#v, want allowed remote-allow", after.Decision)
	}
	if got := manager.current.remotePolicySnapshots(); len(got) != 1 {
		t.Fatalf("remoteSnapshots len = %d, want 1", len(got))
	}
	if got := policyNames(manager.current.mergedPolicyConfigs()); !slices.Equal(got, []string{"static-allow", "remote-allow"}) {
		t.Fatalf("merged policy names = %#v, want %#v", got, []string{"static-allow", "remote-allow"})
	}
}

func TestManagerKeepsLastGoodRemotePolicySnapshotOnFailure(t *testing.T) {
	restorePolicyDiscoveryRunner := newPolicyDiscoveryRunner
	t.Cleanup(func() {
		newPolicyDiscoveryRunner = restorePolicyDiscoveryRunner
	})

	runner := &fakePolicyDiscoveryRunner{}
	newPolicyDiscoveryRunner = func(ctx context.Context, logger *slog.Logger, metrics *appmetrics.Metrics, sources []config.PolicyDiscoverySourceConfig, apply policyDiscoveryApplyFunc) (policyDiscoveryRunner, error) {
		runner.apply = apply
		runner.sources = append([]config.PolicyDiscoverySourceConfig(nil), sources...)
		return runner, nil
	}

	manager := newRuntimeManager(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), appmetrics.New(prometheus.NewRegistry()), "", &reloadableProxyHandler{}, nil)
	defer manager.Close()

	cfg := testRuntimeConfig()
	cfg.Discovery = config.DiscoveryConfig{
		Policies: []config.PolicyDiscoverySourceConfig{{
			Name:     "remote-a",
			Provider: "aws",
			Bucket:   "policies",
		}},
	}
	cfg.Policies = []config.PolicyConfig{
		testRuntimeCIDRPolicy("static-allow", "10.0.0.0/24", "static.example.com"),
	}

	if err := manager.LoadInitial(cfg); err != nil {
		t.Fatalf("LoadInitial() error = %v", err)
	}

	goodSnapshot := policydiscovery.Snapshot{
		Source: config.PolicyDiscoverySourceConfig{Name: "remote-a"},
		Policies: []policydiscovery.DiscoveredPolicy{{
			SourceName: "remote-a",
			Object: policydiscovery.ObjectRef{
				Key: "env/prod/good.yaml",
				URI: "s3://policies/env/prod/good.yaml",
			},
			Policy: testRuntimeCIDRPolicy("remote-allow", "10.1.0.0/24", "remote.example.com"),
		}},
	}
	if err := runner.apply("remote-a", goodSnapshot); err != nil {
		t.Fatalf("apply good snapshot error = %v", err)
	}

	badSnapshot := policydiscovery.Snapshot{
		Source: config.PolicyDiscoverySourceConfig{Name: "remote-a"},
		Policies: []policydiscovery.DiscoveredPolicy{{
			SourceName: "remote-a",
			Object: policydiscovery.ObjectRef{
				Key: "env/prod/bad.yaml",
				URI: "s3://policies/env/prod/bad.yaml",
			},
			Policy: testRuntimeCIDRPolicy("static-allow", "10.2.0.0/24", "duplicate.example.com"),
		}},
	}
	err := runner.apply("remote-a", badSnapshot)
	if err == nil {
		t.Fatal("expected duplicate remote snapshot update to fail")
	}

	after, err := manager.Simulate(appmetrics.SimulationRequest{
		Protocol: "connect",
		SourceIP: "10.1.0.10",
		FQDN:     "remote.example.com",
		Port:     443,
	})
	if err != nil {
		t.Fatalf("Simulate() after failed update error = %v", err)
	}
	if after.Decision == nil || after.Decision.Policy != "remote-allow" || !after.Decision.Allowed {
		t.Fatalf("Simulate() decision after failed update = %#v, want retained remote-allow", after.Decision)
	}
	if got := policyNames(manager.current.mergedPolicyConfigs()); !slices.Equal(got, []string{"static-allow", "remote-allow"}) {
		t.Fatalf("merged policy names = %#v, want %#v", got, []string{"static-allow", "remote-allow"})
	}
	if got := manager.current.remotePolicySnapshots()["remote-a"].Policies[0].Policy.Name; got != "remote-allow" {
		t.Fatalf("retained remote policy = %q, want remote-allow", got)
	}
}

func TestManagerReloadCarriesForwardRemotePoliciesOnlyForMatchingSources(t *testing.T) {
	stubRuntimeKubernetesProvider(t)
	restorePolicyDiscoveryRunner := newPolicyDiscoveryRunner
	t.Cleanup(func() {
		newPolicyDiscoveryRunner = restorePolicyDiscoveryRunner
	})

	initialRunner := &fakePolicyDiscoveryRunner{}
	reloadRunner := &fakePolicyDiscoveryRunner{}
	runnerCalls := 0
	newPolicyDiscoveryRunner = func(ctx context.Context, logger *slog.Logger, metrics *appmetrics.Metrics, sources []config.PolicyDiscoverySourceConfig, apply policyDiscoveryApplyFunc) (policyDiscoveryRunner, error) {
		runnerCalls++
		var runner *fakePolicyDiscoveryRunner
		switch runnerCalls {
		case 1:
			runner = initialRunner
		case 2:
			runner = reloadRunner
		default:
			t.Fatalf("unexpected policy discovery runner build %d", runnerCalls)
		}
		runner.apply = apply
		runner.sources = append([]config.PolicyDiscoverySourceConfig(nil), sources...)
		return runner, nil
	}

	manager := newRuntimeManager(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), appmetrics.New(prometheus.NewRegistry()), "", &reloadableProxyHandler{}, nil)
	defer manager.Close()

	cfg := testRuntimeConfig()
	cfg.Discovery.Policies = []config.PolicyDiscoverySourceConfig{
		testPolicyDiscoverySource("remote-a", "bucket-a", "policies/team-a"),
	}
	cfg.Policies = []config.PolicyConfig{
		testRuntimeCIDRPolicy("static-allow", "10.0.0.0/24", "static.example.com"),
	}
	if err := manager.LoadInitial(cfg); err != nil {
		t.Fatalf("LoadInitial() error = %v", err)
	}

	if err := initialRunner.apply("remote-a", policydiscovery.Snapshot{
		Source: testPolicyDiscoverySource("remote-a", "bucket-a", "policies/team-a"),
		Policies: []policydiscovery.DiscoveredPolicy{{
			SourceName: "remote-a",
			Object: policydiscovery.ObjectRef{
				Key:      "policies/team-a/allow.yaml",
				URI:      "s3://bucket-a/policies/team-a/allow.yaml",
				Revision: "\"rev-a\"",
			},
			Policy: testRuntimeCIDRPolicy("remote-allow", "10.1.0.0/24", "remote.example.com"),
		}},
	}); err != nil {
		t.Fatalf("apply remote snapshot error = %v", err)
	}

	nextCfg := testRuntimeConfig()
	nextCfg.Discovery.Policies = []config.PolicyDiscoverySourceConfig{
		testPolicyDiscoverySource("remote-a", "bucket-b", "policies/team-a"),
	}
	nextCfg.Policies = []config.PolicyConfig{
		testRuntimeCIDRPolicy("static-allow", "10.0.0.0/24", "static.example.com"),
	}
	if err := manager.applyConfig(nextCfg, true); err != nil {
		t.Fatalf("applyConfig() error = %v", err)
	}

	resp, err := manager.Simulate(appmetrics.SimulationRequest{
		Protocol: "connect",
		SourceIP: "10.1.0.10",
		FQDN:     "remote.example.com",
		Port:     443,
	})
	if err != nil {
		t.Fatalf("Simulate() error = %v", err)
	}
	if resp.Decision == nil || resp.Decision.Allowed {
		t.Fatalf("Simulate() decision = %#v, want denied result", resp.Decision)
	}
	if got := manager.current.remotePolicySnapshots(); len(got) != 0 {
		t.Fatalf("remoteSnapshots len = %d, want 0", len(got))
	}
	if got := policyNames(manager.current.mergedPolicyConfigs()); !slices.Equal(got, []string{"static-allow"}) {
		t.Fatalf("merged policy names = %#v, want %#v", got, []string{"static-allow"})
	}
}

func TestManagerReloadDeletesMetricsForRemovedPolicyDiscoverySources(t *testing.T) {
	stubRuntimeKubernetesProvider(t)
	restorePolicyDiscoveryRunner := newPolicyDiscoveryRunner
	t.Cleanup(func() {
		newPolicyDiscoveryRunner = restorePolicyDiscoveryRunner
	})

	newPolicyDiscoveryRunner = func(ctx context.Context, logger *slog.Logger, metrics *appmetrics.Metrics, sources []config.PolicyDiscoverySourceConfig, apply policyDiscoveryApplyFunc) (policyDiscoveryRunner, error) {
		return &fakePolicyDiscoveryRunner{
			apply:   apply,
			sources: append([]config.PolicyDiscoverySourceConfig(nil), sources...),
		}, nil
	}

	reg := prometheus.NewRegistry()
	m := appmetrics.New(reg)
	manager := newRuntimeManager(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), m, "", &reloadableProxyHandler{}, nil)
	defer manager.Close()

	cfg := testRuntimeConfig()
	cfg.Discovery.Policies = []config.PolicyDiscoverySourceConfig{
		testPolicyDiscoverySource("remote-a", "bucket-a", "policies/team-a"),
		testPolicyDiscoverySource("remote-b", "bucket-b", "policies/team-b"),
	}
	if err := manager.LoadInitial(cfg); err != nil {
		t.Fatalf("LoadInitial() error = %v", err)
	}

	m.PolicyDiscoveryObjectsActive.WithLabelValues("remote-a", "aws").Set(1)
	m.PolicyDiscoveryPoliciesActive.WithLabelValues("remote-a", "aws").Set(2)
	m.PolicyDiscoveryLastSuccess.WithLabelValues("remote-a", "aws").Set(1700000300)
	m.PolicyDiscoveryObjectsActive.WithLabelValues("remote-b", "aws").Set(3)
	m.PolicyDiscoveryPoliciesActive.WithLabelValues("remote-b", "aws").Set(4)
	m.PolicyDiscoveryLastSuccess.WithLabelValues("remote-b", "aws").Set(1700000400)

	nextCfg := testRuntimeConfig()
	nextCfg.Discovery.Policies = []config.PolicyDiscoverySourceConfig{
		testPolicyDiscoverySource("remote-b", "bucket-b", "policies/team-b"),
	}
	if err := manager.applyConfig(nextCfg, true); err != nil {
		t.Fatalf("applyConfig() error = %v", err)
	}

	assertPolicyDiscoveryMetricAbsent(t, reg, "aegis_policy_discovery_objects_active", "remote-a", "aws")
	assertPolicyDiscoveryMetricAbsent(t, reg, "aegis_policy_discovery_policies_active", "remote-a", "aws")
	assertPolicyDiscoveryMetricAbsent(t, reg, "aegis_policy_discovery_last_success_timestamp_seconds", "remote-a", "aws")
	assertPolicyDiscoveryMetricPresent(t, reg, "aegis_policy_discovery_objects_active", "remote-b", "aws")
	assertPolicyDiscoveryMetricPresent(t, reg, "aegis_policy_discovery_policies_active", "remote-b", "aws")
	assertPolicyDiscoveryMetricPresent(t, reg, "aegis_policy_discovery_last_success_timestamp_seconds", "remote-b", "aws")
}

func runtimeTestKubernetesSubjects() config.PolicySubjectsConfig {
	return config.PolicySubjectsConfig{
		Kubernetes: &config.KubernetesSubjectConfig{
			DiscoveryNames: []string{"cluster-a"},
			Namespaces:     []string{"default"},
			MatchLabels: map[string]string{
				"app": "web",
			},
		},
	}
}

func runtimeTestKubernetesDiscovery() config.DiscoveryConfig {
	return config.DiscoveryConfig{
		Kubernetes: []config.KubernetesDiscoveryConfig{{
			Name: "cluster-a",
			Auth: config.KubernetesAuthConfig{
				Provider: "inCluster",
			},
		}},
	}
}

func stubRuntimeKubernetesProvider(t *testing.T) {
	t.Helper()

	restoreRuntime := newIdentityDiscoveryRuntime
	t.Cleanup(func() {
		newIdentityDiscoveryRuntime = restoreRuntime
	})

	newIdentityDiscoveryRuntime = func(cfg config.DiscoveryConfig, logger *slog.Logger, m *appmetrics.Metrics) interface {
		Start(context.Context) (proxy.IdentityResolver, error)
	} {
		return fakeIdentityDiscoveryRuntime{
			start: func(context.Context) (proxy.IdentityResolver, error) {
				return identity.NewCompositeResolver([]identity.ProviderHandle{{
					Name: "cluster-a",
					Kind: "kubernetes",
					Resolver: fakeStartableResolver{
						identity: &identity.Identity{
							Source:   "kubernetes",
							Provider: "cluster-a",
							Name:     "default/web",
							Labels: map[string]string{
								"kubernetes.io/namespace": "default",
								"app":                     "web",
							},
						},
					},
				}}, logger, m), nil
			},
		}
	}
}

func serveReloadableHandler(t *testing.T, handler http.Handler) string {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)

	return resp.Body.String()
}

func writeRuntimeConfig(t *testing.T, contents string) string {
	t.Helper()

	dir := t.TempDir()
	path := dir + "/aegis.yaml"
	writeRuntimeConfigAt(t, path, contents)
	return path
}

func writeRuntimeConfigAt(t *testing.T, path string, contents string) {
	t.Helper()

	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
}

func runtimeConfigYAML(policyName string, proxyListen string, metricsListen string, proxyProtocol bool, proxyProtocolTimeout string) string {
	proxyProtocolBlock := ""
	if proxyProtocol {
		proxyProtocolBlock = "  proxyProtocol:\n    enabled: true\n"
		if proxyProtocolTimeout != "" {
			proxyProtocolBlock += "    headerTimeout: " + proxyProtocolTimeout + "\n"
		}
	}

	return "proxy:\n" +
		"  listen: \"" + proxyListen + "\"\n" +
		proxyProtocolBlock +
		"metrics:\n" +
		"  listen: \"" + metricsListen + "\"\n" +
		"dns:\n" +
		"  cache_ttl: 30s\n" +
		"  timeout: 5s\n" +
		"  servers: []\n" +
		"discovery:\n" +
		"  kubernetes:\n" +
		"    - name: cluster-a\n" +
		"      auth:\n" +
		"        provider: inCluster\n" +
		"policies:\n" +
		"  - name: " + policyName + "\n" +
		"    subjects:\n" +
		"      kubernetes:\n" +
		"        discoveryNames: [\"cluster-a\"]\n" +
		"        namespaces: [\"default\"]\n" +
		"        matchLabels:\n" +
		"          app: web\n" +
		"    egress:\n" +
		"      - fqdn: \"example.com\"\n" +
		"        ports: [80]\n" +
		"        tls:\n" +
		"          mode: mitm\n" +
		"        http:\n" +
		"          allowedMethods: [\"GET\"]\n" +
		"          allowedPaths: [\"/*\"]\n"
}

func runtimeConfigYAMLWithShutdownGrace(policyName string, proxyListen string, metricsListen string, grace time.Duration) string {
	return runtimeConfigYAML(policyName, proxyListen, metricsListen, false, "") +
		"shutdown:\n" +
		"  gracePeriod: " + grace.String() + "\n"
}

func testRuntimeConfig() config.Config {
	return config.Config{
		Proxy: config.ProxyConfig{
			Listen: ":3128",
		},
		Metrics: config.MetricsConfig{
			Listen: ":9090",
		},
		DNS: config.DNSConfig{
			CacheTTL: 30 * time.Second,
			Timeout:  5 * time.Second,
		},
		Shutdown: config.ShutdownConfig{
			GracePeriod: 10 * time.Second,
		},
		Discovery: runtimeTestKubernetesDiscovery(),
		Policies: []config.PolicyConfig{{
			Name:     "allow-example",
			Subjects: runtimeTestKubernetesSubjects(),
			Egress: []config.EgressRuleConfig{{
				FQDN:  "example.com",
				Ports: []int{80},
				TLS:   config.TLSRuleConfig{Mode: "mitm"},
				HTTP: &config.HTTPRuleConfig{
					AllowedMethods: []string{"GET"},
					AllowedPaths:   []string{"/*"},
				},
			}},
		}},
	}
}

func testRuntimeCIDRPolicy(name string, cidr string, fqdn string) config.PolicyConfig {
	return config.PolicyConfig{
		Name:        name,
		Enforcement: config.EnforcementEnforce,
		Subjects: config.PolicySubjectsConfig{
			CIDRs: []string{cidr},
		},
		Egress: []config.EgressRuleConfig{{
			FQDN:  fqdn,
			Ports: []int{443},
			TLS: config.TLSRuleConfig{
				Mode: "passthrough",
			},
		}},
	}
}

func testPolicyDiscoverySource(name string, bucket string, prefix string) config.PolicyDiscoverySourceConfig {
	return config.PolicyDiscoverySourceConfig{
		Name:     name,
		Provider: "aws",
		Bucket:   bucket,
		Prefix:   prefix,
	}
}

func policyNames(policies []config.PolicyConfig) []string {
	names := make([]string, 0, len(policies))
	for _, cfg := range policies {
		names = append(names, cfg.Name)
	}
	return names
}

func assertPolicyDiscoveryMetricPresent(t *testing.T, reg *prometheus.Registry, name string, source string, provider string) {
	t.Helper()

	if findMetric(t, reg, name, map[string]string{"source": source, "provider": provider}) == nil {
		t.Fatalf("metric %q for source=%q provider=%q not found", name, source, provider)
	}
}

func assertPolicyDiscoveryMetricAbsent(t *testing.T, reg *prometheus.Registry, name string, source string, provider string) {
	t.Helper()

	if findMetric(t, reg, name, map[string]string{"source": source, "provider": provider}) != nil {
		t.Fatalf("metric %q for source=%q provider=%q still present", name, source, provider)
	}
}

type fakeStartableResolver struct {
	identity *identity.Identity
	startErr error
	startFn  func(context.Context, time.Duration) error
}

func (r fakeStartableResolver) Start(ctx context.Context, startupTimeout time.Duration) error {
	if r.startFn != nil {
		return r.startFn(ctx, startupTimeout)
	}
	return r.startErr
}

func (r fakeStartableResolver) Resolve(net.IP) (*identity.Identity, error) {
	return r.identity, nil
}

type fakeIdentityDiscoveryRuntime struct {
	start func(context.Context) (proxy.IdentityResolver, error)
}

func (r fakeIdentityDiscoveryRuntime) Start(ctx context.Context) (proxy.IdentityResolver, error) {
	if r.start == nil {
		return nil, nil
	}
	return r.start(ctx)
}

type fakeHandlerProvider struct {
	handler http.Handler
}

func (p fakeHandlerProvider) Handler() http.Handler {
	return p.handler
}

type fakePolicyDiscoveryRunner struct {
	apply        func(string, policydiscovery.Snapshot) error
	sources      []config.PolicyDiscoverySourceConfig
	startFn      func(*fakePolicyDiscoveryRunner) error
	releaseStart chan struct{}
	startCalls   int
	closeCalls   int
}

func (r *fakePolicyDiscoveryRunner) Start() error {
	r.startCalls++
	if r.releaseStart == nil {
		r.releaseStart = make(chan struct{})
	}
	if r.startFn != nil {
		return r.startFn(r)
	}
	return nil
}

func (r *fakePolicyDiscoveryRunner) Close() error {
	r.closeCalls++
	return nil
}

func counterValue(t *testing.T, reg *prometheus.Registry, name string, labels map[string]string) float64 {
	t.Helper()

	metric := findMetric(t, reg, name, labels)
	if metric == nil {
		return 0
	}
	if metric.Counter == nil {
		t.Fatalf("metric %q is not a counter", name)
	}

	return metric.Counter.GetValue()
}

func findMetric(t *testing.T, reg *prometheus.Registry, name string, labels map[string]string) *dto.Metric {
	t.Helper()

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v", err)
	}

	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.GetMetric() {
			if hasLabels(metric, labels) {
				return metric
			}
		}
	}

	return nil
}

func hasLabels(metric *dto.Metric, want map[string]string) bool {
	if len(want) == 0 {
		return len(metric.GetLabel()) == 0
	}
	if len(metric.GetLabel()) != len(want) {
		return false
	}

	for _, pair := range metric.GetLabel() {
		if want[pair.GetName()] != pair.GetValue() {
			return false
		}
	}

	return true
}
