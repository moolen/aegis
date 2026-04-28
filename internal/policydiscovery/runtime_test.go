package policydiscovery

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/moolen/aegis/internal/config"
	appmetrics "github.com/moolen/aegis/internal/metrics"
)

func TestCompileMergedEngineCombinesStaticAndRemotePolicies(t *testing.T) {
	staticPolicies := []config.PolicyConfig{
		testPolicyConfig("static-allow", "10.0.0.0/24", "static.example.com"),
	}
	snapshots := map[string]Snapshot{
		"prod-aws": {
			Source: config.PolicyDiscoverySourceConfig{Name: "prod-aws"},
			Policies: []DiscoveredPolicy{
				{
					SourceName: "prod-aws",
					Policy:     testPolicyConfig("remote-allow", "10.1.0.0/24", "remote.example.com"),
				},
			},
		},
	}

	engine, merged, err := CompileMergedEngine(staticPolicies, snapshots)
	if err != nil {
		t.Fatalf("CompileMergedEngine() error = %v", err)
	}
	if engine == nil {
		t.Fatal("CompileMergedEngine() engine = nil")
	}

	want := []config.PolicyConfig{
		testPolicyConfig("static-allow", "10.0.0.0/24", "static.example.com"),
		testPolicyConfig("remote-allow", "10.1.0.0/24", "remote.example.com"),
	}
	if !reflect.DeepEqual(merged, want) {
		t.Fatalf("CompileMergedEngine() merged = %#v, want %#v", merged, want)
	}
}

func TestMergePoliciesKeepsStaticFirstAndOrdersRemoteDeterministically(t *testing.T) {
	staticPolicies := []config.PolicyConfig{
		testPolicyConfig("static-first", "10.0.0.0/24", "static.example.com"),
	}
	snapshots := map[string]Snapshot{
		"source-b": {
			Source: config.PolicyDiscoverySourceConfig{Name: "source-b"},
			Policies: []DiscoveredPolicy{
				{
					SourceName: "source-b",
					Object:     ObjectRef{URI: "s3://bucket/z.yaml"},
					Policy:     testPolicyConfig("remote-z", "10.3.0.0/24", "z.example.com"),
				},
			},
		},
		"source-a": {
			Source: config.PolicyDiscoverySourceConfig{Name: "source-a"},
			Policies: []DiscoveredPolicy{
				{
					SourceName: "source-a",
					Object:     ObjectRef{URI: "s3://bucket/b.yaml"},
					Policy:     testPolicyConfig("remote-b", "10.2.0.0/24", "b.example.com"),
				},
				{
					SourceName: "source-a",
					Object:     ObjectRef{URI: "s3://bucket/a.yaml"},
					Policy:     testPolicyConfig("remote-a", "10.1.0.0/24", "a.example.com"),
				},
			},
		},
	}

	merged, err := MergePolicies(staticPolicies, snapshots)
	if err != nil {
		t.Fatalf("MergePolicies() error = %v", err)
	}

	want := []config.PolicyConfig{
		testPolicyConfig("static-first", "10.0.0.0/24", "static.example.com"),
		testPolicyConfig("remote-a", "10.1.0.0/24", "a.example.com"),
		testPolicyConfig("remote-b", "10.2.0.0/24", "b.example.com"),
		testPolicyConfig("remote-z", "10.3.0.0/24", "z.example.com"),
	}
	if !reflect.DeepEqual(merged, want) {
		t.Fatalf("MergePolicies() = %#v, want %#v", merged, want)
	}
}

func TestMergePoliciesRejectsDuplicatePolicyNamesAcrossSources(t *testing.T) {
	staticPolicies := []config.PolicyConfig{
		testPolicyConfig("shared-name", "10.0.0.0/24", "static.example.com"),
	}
	snapshots := map[string]Snapshot{
		"prod-aws": {
			Source: config.PolicyDiscoverySourceConfig{Name: "prod-aws"},
			Policies: []DiscoveredPolicy{
				{
					SourceName: "prod-aws",
					Policy:     testPolicyConfig("shared-name", "10.1.0.0/24", "remote.example.com"),
				},
			},
		},
	}

	_, err := MergePolicies(staticPolicies, snapshots)
	if err == nil {
		t.Fatal("expected duplicate-name error")
	}
	if !strings.Contains(err.Error(), "shared-name") || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("error = %v, want duplicate shared-name error", err)
	}
}

func TestReplaceSourceSnapshotRemovesDeletedDocumentsFromActiveState(t *testing.T) {
	current := map[string]Snapshot{
		"prod-aws": {
			Source: config.PolicyDiscoverySourceConfig{Name: "prod-aws"},
			Policies: []DiscoveredPolicy{
				{
					SourceName: "prod-aws",
					Policy:     testPolicyConfig("remote-a", "10.1.0.0/24", "a.example.com"),
				},
				{
					SourceName: "prod-aws",
					Policy:     testPolicyConfig("remote-b", "10.2.0.0/24", "b.example.com"),
				},
			},
		},
	}

	replaced := ReplaceSourceSnapshot(current, "prod-aws", Snapshot{
		Source: config.PolicyDiscoverySourceConfig{Name: "different-name"},
		Policies: []DiscoveredPolicy{
			{
				SourceName: "prod-aws",
				Policy:     testPolicyConfig("remote-a", "10.1.0.0/24", "a.example.com"),
			},
		},
	})

	merged, err := MergePolicies(nil, replaced)
	if err != nil {
		t.Fatalf("MergePolicies() error = %v", err)
	}

	want := []config.PolicyConfig{
		testPolicyConfig("remote-a", "10.1.0.0/24", "a.example.com"),
	}
	if !reflect.DeepEqual(merged, want) {
		t.Fatalf("merged policies = %#v, want %#v", merged, want)
	}
	if _, exists := replaced["different-name"]; exists {
		t.Fatal("replacement should use explicit source key, not snapshot payload name")
	}
}

func TestRunnerAppliesFullSnapshotOnPoll(t *testing.T) {
	source := testPolicyDiscoverySource("prod-aws")
	reg := prometheus.NewRegistry()
	metrics := appmetrics.New(reg)
	tickers := &fakeRunnerTickerFactory{}
	collect := &fakeSnapshotCollector{
		results: []fakeCollectResult{{
			snapshot: Snapshot{
				Source: source,
				Objects: []ObjectRef{
					{Key: "tenants/a.yaml", URI: "s3://bucket/tenants/a.yaml", Revision: "\"rev-a\""},
				},
				Policies: []DiscoveredPolicy{
					{
						SourceName: source.Name,
						Object:     ObjectRef{Key: "tenants/a.yaml", URI: "s3://bucket/tenants/a.yaml", Revision: "\"rev-a\""},
						Policy:     testPolicyConfig("remote-allow", "10.1.0.0/24", "remote.example.com"),
					},
				},
			},
		}},
	}

	var mu sync.Mutex
	activeSnapshots := map[string]Snapshot{}
	applied := make(chan struct{}, 2)
	runner, err := newRunner(
		context.Background(),
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		metrics,
		[]config.PolicyDiscoverySourceConfig{source},
		func(sourceName string, snapshot Snapshot) error {
			mu.Lock()
			activeSnapshots = ReplaceSourceSnapshot(activeSnapshots, sourceName, snapshot)
			mu.Unlock()
			applied <- struct{}{}
			return nil
		},
		runnerDeps{
			newClient: func(context.Context, config.PolicyDiscoverySourceConfig) (ObjectStoreClient, error) {
				return &fakeRunnerObjectStoreClient{}, nil
			},
			collectSnapshot: collect.collect,
			newTicker:       tickers.New,
			now: func() time.Time {
				return time.Unix(1700000000, 0)
			},
		},
	)
	if err != nil {
		t.Fatalf("newRunner() error = %v", err)
	}
	defer runner.Close()

	if err := runner.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	waitForSignal(t, applied, "initial snapshot apply")

	mu.Lock()
	active := cloneSnapshotMap(activeSnapshots)
	mu.Unlock()
	merged, err := MergePolicies(nil, active)
	if err != nil {
		t.Fatalf("MergePolicies() error = %v", err)
	}
	wantMerged := []config.PolicyConfig{
		testPolicyConfig("remote-allow", "10.1.0.0/24", "remote.example.com"),
	}
	if !reflect.DeepEqual(merged, wantMerged) {
		t.Fatalf("merged policies = %#v, want %#v", merged, wantMerged)
	}
	if got := counterValueForLabels(t, reg, "aegis_policy_discovery_polls_total", map[string]string{"source": "prod-aws", "provider": "aws", "result": "success"}); got != 1 {
		t.Fatalf("poll success metric = %v, want 1", got)
	}
	if got := counterValueForLabels(t, reg, "aegis_policy_discovery_snapshot_applies_total", map[string]string{"source": "prod-aws", "provider": "aws", "result": "success"}); got != 1 {
		t.Fatalf("snapshot apply success metric = %v, want 1", got)
	}
	if got := gaugeValueForLabels(t, reg, "aegis_policy_discovery_objects_active", map[string]string{"source": "prod-aws", "provider": "aws"}); got != 1 {
		t.Fatalf("objects gauge = %v, want 1", got)
	}
	if got := gaugeValueForLabels(t, reg, "aegis_policy_discovery_policies_active", map[string]string{"source": "prod-aws", "provider": "aws"}); got != 1 {
		t.Fatalf("policies gauge = %v, want 1", got)
	}
	if got := gaugeValueForLabels(t, reg, "aegis_policy_discovery_last_success_timestamp_seconds", map[string]string{"source": "prod-aws", "provider": "aws"}); got != 1700000000 {
		t.Fatalf("last success gauge = %v, want 1700000000", got)
	}
}

func TestRunnerKeepsLastGoodSnapshotWhenPollFails(t *testing.T) {
	source := testPolicyDiscoverySource("prod-aws")
	reg := prometheus.NewRegistry()
	metrics := appmetrics.New(reg)
	tickers := &fakeRunnerTickerFactory{}
	collect := &fakeSnapshotCollector{
		results: []fakeCollectResult{
			{
				snapshot: Snapshot{
					Source: source,
					Objects: []ObjectRef{
						{Key: "tenants/a.yaml", URI: "s3://bucket/tenants/a.yaml", Revision: "\"rev-a\""},
					},
					Policies: []DiscoveredPolicy{
						{
							SourceName: source.Name,
							Object:     ObjectRef{Key: "tenants/a.yaml", URI: "s3://bucket/tenants/a.yaml", Revision: "\"rev-a\""},
							Policy:     testPolicyConfig("remote-allow", "10.1.0.0/24", "remote.example.com"),
						},
					},
				},
			},
			{
				err: errors.New("list failed"),
			},
		},
	}

	var mu sync.Mutex
	activeSnapshots := map[string]Snapshot{}
	applied := make(chan struct{}, 2)
	runner, err := newRunner(
		context.Background(),
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		metrics,
		[]config.PolicyDiscoverySourceConfig{source},
		func(sourceName string, snapshot Snapshot) error {
			mu.Lock()
			activeSnapshots = ReplaceSourceSnapshot(activeSnapshots, sourceName, snapshot)
			mu.Unlock()
			applied <- struct{}{}
			return nil
		},
		runnerDeps{
			newClient: func(context.Context, config.PolicyDiscoverySourceConfig) (ObjectStoreClient, error) {
				return &fakeRunnerObjectStoreClient{}, nil
			},
			collectSnapshot: collect.collect,
			newTicker:       tickers.New,
			now: func() time.Time {
				return time.Unix(1700000100, 0)
			},
		},
	)
	if err != nil {
		t.Fatalf("newRunner() error = %v", err)
	}
	defer runner.Close()

	if err := runner.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	waitForSignal(t, applied, "initial snapshot apply")

	ticker := tickers.WaitForTicker(t)
	ticker.Tick(time.Unix(1700000101, 0))
	collect.WaitForCall(t, 2)

	select {
	case <-applied:
		t.Fatal("unexpected snapshot apply after poll failure")
	case <-time.After(50 * time.Millisecond):
	}

	mu.Lock()
	active := cloneSnapshotMap(activeSnapshots)
	mu.Unlock()
	merged, err := MergePolicies(nil, active)
	if err != nil {
		t.Fatalf("MergePolicies() error = %v", err)
	}
	wantMerged := []config.PolicyConfig{
		testPolicyConfig("remote-allow", "10.1.0.0/24", "remote.example.com"),
	}
	if !reflect.DeepEqual(merged, wantMerged) {
		t.Fatalf("merged policies = %#v, want %#v", merged, wantMerged)
	}
	if got := counterValueForLabels(t, reg, "aegis_policy_discovery_polls_total", map[string]string{"source": "prod-aws", "provider": "aws", "result": "success"}); got != 1 {
		t.Fatalf("poll success metric = %v, want 1", got)
	}
	if got := counterValueForLabels(t, reg, "aegis_policy_discovery_polls_total", map[string]string{"source": "prod-aws", "provider": "aws", "result": "error"}); got != 1 {
		t.Fatalf("poll error metric = %v, want 1", got)
	}
	if got := counterValueForLabels(t, reg, "aegis_policy_discovery_snapshot_applies_total", map[string]string{"source": "prod-aws", "provider": "aws", "result": "success"}); got != 1 {
		t.Fatalf("snapshot apply success metric = %v, want 1", got)
	}
	if got := gaugeValueForLabels(t, reg, "aegis_policy_discovery_policies_active", map[string]string{"source": "prod-aws", "provider": "aws"}); got != 1 {
		t.Fatalf("policies gauge = %v, want 1", got)
	}
}

func TestRunnerRemovesDeletedDocumentsAcrossPolls(t *testing.T) {
	source := testPolicyDiscoverySource("prod-aws")
	reg := prometheus.NewRegistry()
	metrics := appmetrics.New(reg)
	tickers := &fakeRunnerTickerFactory{}
	collect := &fakeSnapshotCollector{
		results: []fakeCollectResult{
			{
				snapshot: Snapshot{
					Source: source,
					Objects: []ObjectRef{
						{Key: "tenants/a.yaml", URI: "s3://bucket/tenants/a.yaml", Revision: "\"rev-a\""},
						{Key: "tenants/b.yaml", URI: "s3://bucket/tenants/b.yaml", Revision: "\"rev-b\""},
					},
					Policies: []DiscoveredPolicy{
						{
							SourceName: source.Name,
							Object:     ObjectRef{Key: "tenants/a.yaml", URI: "s3://bucket/tenants/a.yaml", Revision: "\"rev-a\""},
							Policy:     testPolicyConfig("remote-a", "10.1.0.0/24", "a.example.com"),
						},
						{
							SourceName: source.Name,
							Object:     ObjectRef{Key: "tenants/b.yaml", URI: "s3://bucket/tenants/b.yaml", Revision: "\"rev-b\""},
							Policy:     testPolicyConfig("remote-b", "10.2.0.0/24", "b.example.com"),
						},
					},
				},
			},
			{
				snapshot: Snapshot{
					Source: source,
					Objects: []ObjectRef{
						{Key: "tenants/a.yaml", URI: "s3://bucket/tenants/a.yaml", Revision: "\"rev-c\""},
					},
					Policies: []DiscoveredPolicy{
						{
							SourceName: source.Name,
							Object:     ObjectRef{Key: "tenants/a.yaml", URI: "s3://bucket/tenants/a.yaml", Revision: "\"rev-c\""},
							Policy:     testPolicyConfig("remote-a", "10.1.0.0/24", "a.example.com"),
						},
					},
				},
			},
		},
	}

	var mu sync.Mutex
	activeSnapshots := map[string]Snapshot{}
	applied := make(chan struct{}, 4)
	runner, err := newRunner(
		context.Background(),
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		metrics,
		[]config.PolicyDiscoverySourceConfig{source},
		func(sourceName string, snapshot Snapshot) error {
			mu.Lock()
			activeSnapshots = ReplaceSourceSnapshot(activeSnapshots, sourceName, snapshot)
			mu.Unlock()
			applied <- struct{}{}
			return nil
		},
		runnerDeps{
			newClient: func(context.Context, config.PolicyDiscoverySourceConfig) (ObjectStoreClient, error) {
				return &fakeRunnerObjectStoreClient{}, nil
			},
			collectSnapshot: collect.collect,
			newTicker:       tickers.New,
			now: func() time.Time {
				return time.Unix(1700000200, 0)
			},
		},
	)
	if err != nil {
		t.Fatalf("newRunner() error = %v", err)
	}
	defer runner.Close()

	if err := runner.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	waitForSignal(t, applied, "initial snapshot apply")

	ticker := tickers.WaitForTicker(t)
	ticker.Tick(time.Unix(1700000201, 0))
	waitForSignal(t, applied, "replacement snapshot apply")

	mu.Lock()
	active := cloneSnapshotMap(activeSnapshots)
	mu.Unlock()
	merged, err := MergePolicies(nil, active)
	if err != nil {
		t.Fatalf("MergePolicies() error = %v", err)
	}
	wantMerged := []config.PolicyConfig{
		testPolicyConfig("remote-a", "10.1.0.0/24", "a.example.com"),
	}
	if !reflect.DeepEqual(merged, wantMerged) {
		t.Fatalf("merged policies = %#v, want %#v", merged, wantMerged)
	}
	if got := gaugeValueForLabels(t, reg, "aegis_policy_discovery_objects_active", map[string]string{"source": "prod-aws", "provider": "aws"}); got != 1 {
		t.Fatalf("objects gauge = %v, want 1", got)
	}
	if got := gaugeValueForLabels(t, reg, "aegis_policy_discovery_policies_active", map[string]string{"source": "prod-aws", "provider": "aws"}); got != 1 {
		t.Fatalf("policies gauge = %v, want 1", got)
	}
}

func TestDeleteSourceMetricsRemovesActiveSeries(t *testing.T) {
	reg := prometheus.NewRegistry()
	metrics := appmetrics.New(reg)
	source := testPolicyDiscoverySource("prod-aws")
	metrics.PolicyDiscoveryObjectsActive.WithLabelValues("prod-aws", "aws").Set(1)
	metrics.PolicyDiscoveryPoliciesActive.WithLabelValues("prod-aws", "aws").Set(2)
	metrics.PolicyDiscoveryLastSuccess.WithLabelValues("prod-aws", "aws").Set(1700000300)

	DeleteSourceMetrics(metrics, []config.PolicyDiscoverySourceConfig{source})

	if metricExistsForLabels(t, reg, "aegis_policy_discovery_objects_active", map[string]string{"source": "prod-aws", "provider": "aws"}) {
		t.Fatal("objects gauge should be removed")
	}
	if metricExistsForLabels(t, reg, "aegis_policy_discovery_policies_active", map[string]string{"source": "prod-aws", "provider": "aws"}) {
		t.Fatal("policies gauge should be removed")
	}
	if metricExistsForLabels(t, reg, "aegis_policy_discovery_last_success_timestamp_seconds", map[string]string{"source": "prod-aws", "provider": "aws"}) {
		t.Fatal("last success gauge should be removed")
	}
}

func testPolicyConfig(name string, cidr string, fqdn string) config.PolicyConfig {
	return config.PolicyConfig{
		Name:        name,
		Enforcement: "enforce",
		Subjects: config.PolicySubjectsConfig{
			CIDRs: []string{cidr},
		},
		Egress: []config.EgressRuleConfig{
			{
				FQDN:  fqdn,
				Ports: []int{443},
				TLS: config.TLSRuleConfig{
					Mode: "passthrough",
				},
			},
		},
	}
}

func testPolicyDiscoverySource(name string) config.PolicyDiscoverySourceConfig {
	interval := 30 * time.Second
	return config.PolicyDiscoverySourceConfig{
		Name:         name,
		Provider:     "aws",
		Bucket:       "bucket",
		Prefix:       "tenants/",
		PollInterval: &interval,
		Auth: config.PolicyDiscoveryAuthConfig{
			Mode: "default",
		},
	}
}

type fakeCollectResult struct {
	snapshot Snapshot
	err      error
}

type fakeSnapshotCollector struct {
	mu        sync.Mutex
	results   []fakeCollectResult
	callCh    chan int
	callCount int
}

func (c *fakeSnapshotCollector) collect(ctx context.Context, source config.PolicyDiscoverySourceConfig, client ObjectStoreClient) (Snapshot, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.callCh == nil {
		c.callCh = make(chan int, 8)
	}
	index := c.callCount
	c.callCount++
	c.callCh <- c.callCount
	if index >= len(c.results) {
		return Snapshot{}, errors.New("unexpected poll")
	}
	result := c.results[index]
	return result.snapshot, result.err
}

func (c *fakeSnapshotCollector) WaitForCall(t *testing.T, want int) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		c.mu.Lock()
		got := c.callCount
		c.mu.Unlock()
		if got >= want {
			return
		}
		select {
		case <-time.After(10 * time.Millisecond):
		case <-deadline:
			t.Fatalf("collector call count = %d, want at least %d", got, want)
		}
	}
}

type fakeRunnerObjectStoreClient struct{}

func (*fakeRunnerObjectStoreClient) List(context.Context, string) ([]ObjectRef, error) {
	return nil, nil
}
func (*fakeRunnerObjectStoreClient) Read(context.Context, ObjectRef) ([]byte, error) { return nil, nil }
func (*fakeRunnerObjectStoreClient) Close() error                                    { return nil }

type fakeRunnerTickerFactory struct {
	mu      sync.Mutex
	tickers []*fakeRunnerTicker
	ready   chan *fakeRunnerTicker
}

func (f *fakeRunnerTickerFactory) New(time.Duration) runnerTicker {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ready == nil {
		f.ready = make(chan *fakeRunnerTicker, 8)
	}
	ticker := &fakeRunnerTicker{ch: make(chan time.Time, 8)}
	f.tickers = append(f.tickers, ticker)
	f.ready <- ticker
	return ticker
}

func (f *fakeRunnerTickerFactory) WaitForTicker(t *testing.T) *fakeRunnerTicker {
	t.Helper()
	f.mu.Lock()
	ready := f.ready
	f.mu.Unlock()
	if ready == nil {
		t.Fatal("ticker factory has not created any ticker")
	}
	select {
	case ticker := <-ready:
		return ticker
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for ticker")
		return nil
	}
}

type fakeRunnerTicker struct {
	ch      chan time.Time
	stopped bool
}

func (t *fakeRunnerTicker) C() <-chan time.Time {
	return t.ch
}

func (t *fakeRunnerTicker) Stop() {
	t.stopped = true
}

func (t *fakeRunnerTicker) Tick(at time.Time) {
	t.ch <- at
}

func waitForSignal(t *testing.T, ch <-chan struct{}, label string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %s", label)
	}
}

func cloneSnapshotMap(src map[string]Snapshot) map[string]Snapshot {
	if src == nil {
		return nil
	}
	dst := make(map[string]Snapshot, len(src))
	for key, snapshot := range src {
		dst[key] = snapshot
	}
	return dst
}

func counterValueForLabels(t *testing.T, reg *prometheus.Registry, name string, labels map[string]string) float64 {
	t.Helper()
	metric := mustFindMetricForLabels(t, reg, name, labels)
	if metric.Counter == nil {
		t.Fatalf("metric %q is not a counter", name)
	}
	return metric.Counter.GetValue()
}

func gaugeValueForLabels(t *testing.T, reg *prometheus.Registry, name string, labels map[string]string) float64 {
	t.Helper()
	metric := mustFindMetricForLabels(t, reg, name, labels)
	if metric.Gauge == nil {
		t.Fatalf("metric %q is not a gauge", name)
	}
	return metric.Gauge.GetValue()
}

func mustFindMetricForLabels(t *testing.T, reg *prometheus.Registry, name string, labels map[string]string) *dto.Metric {
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
			if metricHasLabels(metric, labels) {
				return metric
			}
		}
	}
	t.Fatalf("metric %q with labels %#v not found", name, labels)
	return nil
}

func metricExistsForLabels(t *testing.T, reg *prometheus.Registry, name string, labels map[string]string) bool {
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
			if metricHasLabels(metric, labels) {
				return true
			}
		}
	}
	return false
}

func metricHasLabels(metric *dto.Metric, labels map[string]string) bool {
	if len(metric.GetLabel()) != len(labels) {
		return false
	}
	for _, pair := range metric.GetLabel() {
		if labels[pair.GetName()] != pair.GetValue() {
			return false
		}
	}
	return true
}
