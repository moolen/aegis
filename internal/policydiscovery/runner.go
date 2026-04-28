package policydiscovery

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/moolen/aegis/internal/config"
	appmetrics "github.com/moolen/aegis/internal/metrics"
)

const defaultSourcePollInterval = 30 * time.Second

type ApplyFunc func(sourceName string, snapshot Snapshot) error

type Runner struct {
	ctx    context.Context
	cancel context.CancelFunc

	logger  *slog.Logger
	metrics *appmetrics.Metrics
	apply   ApplyFunc
	deps    runnerDeps

	sources []runnerSource

	startOnce sync.Once
	closeOnce sync.Once
	wg        sync.WaitGroup

	closeMu  sync.Mutex
	closeErr error
}

type runnerSource struct {
	source config.PolicyDiscoverySourceConfig
	client ObjectStoreClient
}

type runnerDeps struct {
	newClient       func(context.Context, config.PolicyDiscoverySourceConfig) (ObjectStoreClient, error)
	collectSnapshot func(context.Context, config.PolicyDiscoverySourceConfig, ObjectStoreClient) (Snapshot, error)
	newTicker       func(time.Duration) runnerTicker
	now             func() time.Time
}

type runnerTicker interface {
	C() <-chan time.Time
	Stop()
}

func NewRunner(ctx context.Context, logger *slog.Logger, metrics *appmetrics.Metrics, sources []config.PolicyDiscoverySourceConfig, apply ApplyFunc) (*Runner, error) {
	return newRunner(ctx, logger, metrics, sources, apply, runnerDeps{
		newClient:       NewObjectStoreClient,
		collectSnapshot: CollectSnapshot,
		newTicker: func(interval time.Duration) runnerTicker {
			return &timeRunnerTicker{Ticker: time.NewTicker(interval)}
		},
		now: time.Now,
	})
}

func newRunner(ctx context.Context, logger *slog.Logger, metrics *appmetrics.Metrics, sources []config.PolicyDiscoverySourceConfig, apply ApplyFunc, deps runnerDeps) (*Runner, error) {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if apply == nil {
		apply = func(string, Snapshot) error { return nil }
	}
	if deps.newClient == nil {
		deps.newClient = NewObjectStoreClient
	}
	if deps.collectSnapshot == nil {
		deps.collectSnapshot = CollectSnapshot
	}
	if deps.newTicker == nil {
		deps.newTicker = func(interval time.Duration) runnerTicker {
			return &timeRunnerTicker{Ticker: time.NewTicker(interval)}
		}
	}
	if deps.now == nil {
		deps.now = time.Now
	}

	runnerCtx, cancel := context.WithCancel(ctx)
	r := &Runner{
		ctx:     runnerCtx,
		cancel:  cancel,
		logger:  logger,
		metrics: metrics,
		apply:   apply,
		deps:    deps,
	}

	for _, rawSource := range sources {
		source := normalizeSourceConfig(rawSource)
		client, err := deps.newClient(runnerCtx, source)
		if err != nil {
			cancel()
			_ = r.closeClients()
			return nil, err
		}
		r.sources = append(r.sources, runnerSource{
			source: source,
			client: client,
		})
	}

	return r, nil
}

func (r *Runner) Start() error {
	r.startOnce.Do(func() {
		for _, source := range r.sources {
			source := source
			r.wg.Add(1)
			go func() {
				defer r.wg.Done()
				r.runSource(source)
			}()
		}
	})
	return nil
}

func (r *Runner) Close() error {
	r.closeOnce.Do(func() {
		r.cancel()
		r.wg.Wait()

		r.closeMu.Lock()
		defer r.closeMu.Unlock()
		r.closeErr = r.closeClients()
	})

	r.closeMu.Lock()
	defer r.closeMu.Unlock()
	return r.closeErr
}

func (r *Runner) runSource(source runnerSource) {
	r.pollOnce(source)

	ticker := r.deps.newTicker(pollIntervalForSource(source.source))
	defer ticker.Stop()

	for {
		select {
		case <-r.ctx.Done():
			return
		case <-ticker.C():
			r.pollOnce(source)
		}
	}
}

func (r *Runner) pollOnce(source runnerSource) {
	snapshot, err := r.deps.collectSnapshot(r.ctx, source.source, source.client)
	if err != nil {
		if r.shouldIgnorePollError(err) {
			return
		}
		r.recordPollResult(source.source, "error")
		r.logger.Warn("remote policy discovery poll failed", "source", source.source.Name, "provider", source.source.Provider, "error", err)
		return
	}

	r.recordPollResult(source.source, "success")

	if err := r.apply(source.source.Name, snapshot); err != nil {
		if r.shouldIgnorePollError(err) {
			return
		}
		r.recordSnapshotApplyResult(source.source, "error")
		r.logger.Warn("remote policy discovery snapshot apply failed", "source", source.source.Name, "provider", source.source.Provider, "error", err)
		return
	}

	r.recordSnapshotApplyResult(source.source, "success")
	r.recordAppliedSnapshot(source.source, snapshot)
}

func (r *Runner) shouldIgnorePollError(err error) bool {
	return r.ctx.Err() != nil || errors.Is(err, context.Canceled)
}

func (r *Runner) recordPollResult(source config.PolicyDiscoverySourceConfig, result string) {
	if r.metrics == nil {
		return
	}
	r.metrics.PolicyDiscoveryPollsTotal.WithLabelValues(source.Name, source.Provider, result).Inc()
}

func (r *Runner) recordSnapshotApplyResult(source config.PolicyDiscoverySourceConfig, result string) {
	if r.metrics == nil {
		return
	}
	r.metrics.PolicyDiscoverySnapshotAppliesTotal.WithLabelValues(source.Name, source.Provider, result).Inc()
}

func (r *Runner) recordAppliedSnapshot(source config.PolicyDiscoverySourceConfig, snapshot Snapshot) {
	if r.metrics == nil {
		return
	}
	r.metrics.PolicyDiscoveryObjectsActive.WithLabelValues(source.Name, source.Provider).Set(float64(len(snapshot.Objects)))
	r.metrics.PolicyDiscoveryPoliciesActive.WithLabelValues(source.Name, source.Provider).Set(float64(len(snapshot.Policies)))
	r.metrics.PolicyDiscoveryLastSuccess.WithLabelValues(source.Name, source.Provider).Set(float64(r.deps.now().Unix()))
}

func (r *Runner) closeClients() error {
	var firstErr error
	for _, source := range r.sources {
		if source.client == nil {
			continue
		}
		if err := source.client.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func pollIntervalForSource(source config.PolicyDiscoverySourceConfig) time.Duration {
	if source.PollInterval == nil || *source.PollInterval <= 0 {
		return defaultSourcePollInterval
	}
	return *source.PollInterval
}

type timeRunnerTicker struct {
	*time.Ticker
}

func (t *timeRunnerTicker) C() <-chan time.Time {
	return t.Ticker.C
}
