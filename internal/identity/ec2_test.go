package identity

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	appmetrics "github.com/moolen/aegis/internal/metrics"
)

func TestEC2ProviderResolvesDiscoveredInstance(t *testing.T) {
	source := newFakeEC2InstanceSource()
	source.SetInstances([]EC2Instance{{
		ID:        "i-abc123",
		PrivateIP: "10.0.0.10",
		Tags: map[string]string{
			"aegis/role": "reporting",
			"Name":       "legacy-reporting",
		},
	}})

	provider, err := NewEC2Provider(EC2ProviderConfig{
		Name:         "production-ec2",
		Source:       source,
		PollInterval: 10 * time.Millisecond,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewEC2Provider() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := provider.Start(ctx, time.Second); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	id := requireEventuallyEC2Identity(t, provider, "10.0.0.10")
	if id.Source != "ec2" {
		t.Fatalf("identity source = %q, want %q", id.Source, "ec2")
	}
	if id.Provider != "production-ec2" {
		t.Fatalf("identity provider = %q, want %q", id.Provider, "production-ec2")
	}
	if id.Name != "i-abc123" {
		t.Fatalf("identity name = %q, want %q", id.Name, "i-abc123")
	}
	if id.Labels["aegis/role"] != "reporting" {
		t.Fatalf("aegis label = %#v, want aegis/role=reporting", id.Labels)
	}
	if id.Labels["ec2.tag/Name"] != "legacy-reporting" {
		t.Fatalf("tag label = %#v, want ec2.tag/Name=legacy-reporting", id.Labels)
	}
}

func TestEC2ProviderRemovesMissingInstanceAfterPollRefresh(t *testing.T) {
	source := newFakeEC2InstanceSource()
	source.SetInstances([]EC2Instance{{
		ID:        "i-abc123",
		PrivateIP: "10.0.0.20",
	}})

	provider, err := NewEC2Provider(EC2ProviderConfig{
		Name:         "production-ec2",
		Source:       source,
		PollInterval: 10 * time.Millisecond,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewEC2Provider() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := provider.Start(ctx, time.Second); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	requireEventuallyEC2Identity(t, provider, "10.0.0.20")

	source.SetInstances(nil)
	requireEventuallyNoEC2Identity(t, provider, "10.0.0.20")
}

func TestEC2ProviderRefreshesUpdatedInstances(t *testing.T) {
	source := newFakeEC2InstanceSource()
	source.SetInstances([]EC2Instance{{
		ID:        "i-abc123",
		PrivateIP: "10.0.0.30",
		Tags: map[string]string{
			"aegis/env": "staging",
		},
	}})

	provider, err := NewEC2Provider(EC2ProviderConfig{
		Name:         "production-ec2",
		Source:       source,
		PollInterval: 10 * time.Millisecond,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewEC2Provider() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := provider.Start(ctx, time.Second); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	id := requireEventuallyEC2Identity(t, provider, "10.0.0.30")
	if id.Labels["aegis/env"] != "staging" {
		t.Fatalf("identity labels = %#v, want aegis/env=staging", id.Labels)
	}

	source.SetInstances([]EC2Instance{{
		ID:        "i-def456",
		PrivateIP: "10.0.0.31",
		Tags: map[string]string{
			"aegis/env": "production",
		},
	}})

	requireEventuallyNoEC2Identity(t, provider, "10.0.0.30")
	refreshed := requireEventuallyEC2Identity(t, provider, "10.0.0.31")
	if refreshed.Name != "i-def456" {
		t.Fatalf("identity name = %q, want %q", refreshed.Name, "i-def456")
	}
	if refreshed.Labels["aegis/env"] != "production" {
		t.Fatalf("identity labels = %#v, want aegis/env=production", refreshed.Labels)
	}
}

func TestEC2ProviderStartCancelsOnStartupTimeout(t *testing.T) {
	source := newBlockingEC2InstanceSource()
	provider, err := NewEC2Provider(EC2ProviderConfig{
		Name:         "production-ec2",
		Source:       source,
		PollInterval: time.Second,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewEC2Provider() error = %v", err)
	}

	err = provider.Start(context.Background(), 20*time.Millisecond)
	if err == nil {
		t.Fatal("expected startup timeout")
	}
	if !waitForEC2Signal(source.called, time.Second) {
		t.Fatal("Instances() was never called")
	}
	if !waitForEC2Signal(source.canceled, time.Second) {
		t.Fatal("startup timeout did not cancel source context")
	}
}

func TestEC2ProviderStartReturnsWhenLifecycleCancelled(t *testing.T) {
	source := newBlockingEC2InstanceSource()
	provider, err := NewEC2Provider(EC2ProviderConfig{
		Name:         "production-ec2",
		Source:       source,
		PollInterval: time.Second,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewEC2Provider() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- provider.Start(ctx, time.Minute)
	}()

	if !waitForEC2Signal(source.called, time.Second) {
		t.Fatal("Instances() was never called")
	}

	cancel()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected lifecycle cancellation error")
		}
	case <-time.After(time.Second):
		t.Fatal("Start() did not return after lifecycle cancellation")
	}

	if !waitForEC2Signal(source.canceled, time.Second) {
		t.Fatal("lifecycle cancellation did not cancel source context")
	}
}

func TestEC2ProviderUpdatesIdentityMapGauge(t *testing.T) {
	source := newFakeEC2InstanceSource()
	source.SetInstances([]EC2Instance{{
		ID:        "i-abc123",
		PrivateIP: "10.0.0.80",
	}})

	provider, err := NewEC2Provider(EC2ProviderConfig{
		Name:         "production-ec2",
		Source:       source,
		PollInterval: 10 * time.Millisecond,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewEC2Provider() error = %v", err)
	}

	reg := prometheus.NewRegistry()
	m := appmetrics.New(reg)
	provider.AttachMetrics(m)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := provider.Start(ctx, time.Second); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	requireEventuallyEC2Identity(t, provider, "10.0.0.80")
	if got := gatheredGaugeValue(t, reg, "aegis_identity_map_entries", map[string]string{"provider": "production-ec2", "kind": "ec2"}); got != 1 {
		t.Fatalf("map gauge after start = %v, want 1", got)
	}

	source.SetInstances(nil)
	requireEventuallyNoEC2Identity(t, provider, "10.0.0.80")
	if got := gatheredGaugeValue(t, reg, "aegis_identity_map_entries", map[string]string{"provider": "production-ec2", "kind": "ec2"}); got != 0 {
		t.Fatalf("map gauge after refresh = %v, want 0", got)
	}
}

func TestEC2ProviderTransitionsToStaleAndDownStatusAfterRefreshFailures(t *testing.T) {
	restoreStaleAfter := ProviderStaleAfter
	restoreDownAfter := ProviderDownAfter
	restoreRefreshInterval := ProviderStatusRefreshInterval
	t.Cleanup(func() {
		ProviderStaleAfter = restoreStaleAfter
		ProviderDownAfter = restoreDownAfter
		ProviderStatusRefreshInterval = restoreRefreshInterval
	})

	ProviderStaleAfter = 40 * time.Millisecond
	ProviderDownAfter = 90 * time.Millisecond
	ProviderStatusRefreshInterval = 10 * time.Millisecond

	source := newFakeEC2InstanceSource()
	source.SetInstances([]EC2Instance{{
		ID:        "i-abc123",
		PrivateIP: "10.0.0.80",
	}})

	provider, err := NewEC2Provider(EC2ProviderConfig{
		Name:         "production-ec2",
		Source:       source,
		PollInterval: 10 * time.Millisecond,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewEC2Provider() error = %v", err)
	}

	reg := prometheus.NewRegistry()
	m := appmetrics.New(reg)
	provider.AttachMetrics(m)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := provider.Start(ctx, time.Second); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	if state := provider.ProviderStatus().State; state != ProviderStateActive {
		t.Fatalf("initial state = %q, want %q", state, ProviderStateActive)
	}

	source.SetError(errors.New("ec2 unavailable"))

	requireEventuallyProviderState(t, provider, ProviderStateStale)
	if got := gatheredGaugeValue(t, reg, "aegis_identity_provider_status", map[string]string{"provider": "production-ec2", "kind": "ec2", "status": ProviderStateStale}); got != 1 {
		t.Fatalf("stale status gauge = %v, want 1", got)
	}

	requireEventuallyProviderState(t, provider, ProviderStateDown)
	if got := gatheredGaugeValue(t, reg, "aegis_identity_provider_status", map[string]string{"provider": "production-ec2", "kind": "ec2", "status": ProviderStateDown}); got != 1 {
		t.Fatalf("down status gauge = %v, want 1", got)
	}
}

func requireEventuallyEC2Identity(t *testing.T, provider *EC2Provider, ip string) *Identity {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		id, err := provider.Resolve(net.ParseIP(ip))
		if err != nil {
			t.Fatalf("Resolve() error = %v", err)
		}
		if id != nil {
			return id
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("Resolve(%q) never returned an identity", ip)
	return nil
}

func requireEventuallyNoEC2Identity(t *testing.T, provider *EC2Provider, ip string) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		id, err := provider.Resolve(net.ParseIP(ip))
		if err != nil {
			t.Fatalf("Resolve() error = %v", err)
		}
		if id == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("Resolve(%q) still returned an identity", ip)
}

type fakeEC2InstanceSource struct {
	mu        sync.Mutex
	instances []EC2Instance
	err       error
}

func newFakeEC2InstanceSource() *fakeEC2InstanceSource {
	return &fakeEC2InstanceSource{}
}

func (s *fakeEC2InstanceSource) SetInstances(instances []EC2Instance) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.instances = cloneEC2Instances(instances)
}

func (s *fakeEC2InstanceSource) SetError(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.err = err
}

func (s *fakeEC2InstanceSource) Instances(context.Context, []EC2TagFilter) ([]EC2Instance, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.err != nil {
		return nil, s.err
	}
	return cloneEC2Instances(s.instances), nil
}

func gatheredGaugeValue(t *testing.T, reg *prometheus.Registry, metricName string, labels map[string]string) float64 {
	t.Helper()

	metricFamilies, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v", err)
	}

	for _, family := range metricFamilies {
		if family.GetName() != metricName {
			continue
		}
		for _, metric := range family.GetMetric() {
			pairs := metric.GetLabel()
			if len(pairs) != len(labels) {
				continue
			}

			matched := true
			for _, pair := range pairs {
				if labels[pair.GetName()] != pair.GetValue() {
					matched = false
					break
				}
			}

			if !matched {
				continue
			}

			if metric.GetGauge() == nil {
				t.Fatalf("metric gauge = nil for %s", metricName)
			}
			return metric.GetGauge().GetValue()
		}
		t.Fatalf("metric %s with labels %v not found", metricName, labels)
	}

	t.Fatalf("metric family %s not found", metricName)
	return 0
}

type blockingEC2InstanceSource struct {
	called   chan struct{}
	canceled chan struct{}
}

func newBlockingEC2InstanceSource() *blockingEC2InstanceSource {
	return &blockingEC2InstanceSource{
		called:   make(chan struct{}),
		canceled: make(chan struct{}),
	}
}

func (s *blockingEC2InstanceSource) Instances(ctx context.Context, _ []EC2TagFilter) ([]EC2Instance, error) {
	closeOnceEC2(s.called)
	<-ctx.Done()
	closeOnceEC2(s.canceled)
	return nil, ctx.Err()
}

func cloneEC2Instances(instances []EC2Instance) []EC2Instance {
	if len(instances) == 0 {
		return nil
	}

	cloned := make([]EC2Instance, len(instances))
	for i, instance := range instances {
		cloned[i] = EC2Instance{
			ID:        instance.ID,
			PrivateIP: instance.PrivateIP,
			Tags:      make(map[string]string, len(instance.Tags)),
		}
		for key, value := range instance.Tags {
			cloned[i].Tags[key] = value
		}
	}

	return cloned
}

func waitForEC2Signal(ch <-chan struct{}, timeout time.Duration) bool {
	select {
	case <-ch:
		return true
	case <-time.After(timeout):
		return false
	}
}

func requireEventuallyProviderState(t *testing.T, provider interface{ ProviderStatus() ProviderStatus }, want string) {
	t.Helper()

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if provider.ProviderStatus().State == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("provider state never became %q, last status=%#v", want, provider.ProviderStatus())
}

func closeOnceEC2(ch chan struct{}) {
	select {
	case <-ch:
	default:
		close(ch)
	}
}
