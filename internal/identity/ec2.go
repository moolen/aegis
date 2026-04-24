package identity

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type EC2TagFilter struct {
	Key    string
	Values []string
}

type EC2Instance struct {
	ID        string
	PrivateIP string
	Tags      map[string]string
}

type EC2InstanceSource interface {
	Instances(context.Context, []EC2TagFilter) ([]EC2Instance, error)
}

type EC2ProviderConfig struct {
	Name         string
	Source       EC2InstanceSource
	TagFilters   []EC2TagFilter
	PollInterval time.Duration
}

type EC2Provider struct {
	name         string
	source       EC2InstanceSource
	tagFilters   []EC2TagFilter
	pollInterval time.Duration
	logger       *slog.Logger

	state atomic.Value

	mu      sync.Mutex
	started bool
	cancel  context.CancelFunc
}

func NewEC2Provider(cfg EC2ProviderConfig, logger *slog.Logger) (*EC2Provider, error) {
	if cfg.Name == "" {
		return nil, fmt.Errorf("ec2 provider name is required")
	}
	if cfg.Source == nil {
		return nil, fmt.Errorf("ec2 provider source is required")
	}
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(ioDiscard{}, nil))
	}

	pollInterval := cfg.PollInterval
	if pollInterval <= 0 {
		pollInterval = 30 * time.Second
	}

	provider := &EC2Provider{
		name:         cfg.Name,
		source:       cfg.Source,
		tagFilters:   cloneEC2Filters(cfg.TagFilters),
		pollInterval: pollInterval,
		logger:       logger.With("provider", cfg.Name, "source", "ec2"),
	}
	provider.state.Store(map[string]*Identity{})

	return provider, nil
}

func (p *EC2Provider) Start(ctx context.Context, startupTimeout time.Duration) error {
	p.mu.Lock()
	if p.started {
		p.mu.Unlock()
		return nil
	}

	runCtx, cancel := context.WithCancel(ctx)
	p.started = true
	p.cancel = cancel
	p.mu.Unlock()

	startupCtx := runCtx
	cancelStartup := func() {}
	if startupTimeout > 0 {
		startupCtxWithTimeout, cancelTimeout := context.WithTimeout(runCtx, startupTimeout)
		startupCtx = startupCtxWithTimeout
		cancelStartup = cancelTimeout
	}
	defer cancelStartup()

	if err := p.refresh(startupCtx); err != nil {
		cancel()
		p.resetRunState()
		return fmt.Errorf("sync ec2 provider instances: %w", err)
	}

	go p.poll(runCtx)

	return nil
}

func (p *EC2Provider) Resolve(ip net.IP) (*Identity, error) {
	if ip == nil {
		return nil, nil
	}

	current, _ := p.state.Load().(map[string]*Identity)
	if current == nil {
		return nil, nil
	}

	id := current[ip.String()]
	if id == nil {
		return nil, nil
	}

	return cloneIdentity(id), nil
}

func (p *EC2Provider) poll(ctx context.Context) {
	ticker := time.NewTicker(p.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := p.refresh(ctx); err != nil {
				p.logger.Warn("refresh ec2 provider failed", "error", err)
			}
		}
	}
}

func (p *EC2Provider) refresh(ctx context.Context) error {
	instances, err := p.source.Instances(ctx, cloneEC2Filters(p.tagFilters))
	if err != nil {
		return err
	}

	next := make(map[string]*Identity, len(instances))
	for _, instance := range instances {
		if instance.ID == "" || instance.PrivateIP == "" {
			continue
		}
		next[instance.PrivateIP] = &Identity{
			Source:   "ec2",
			Provider: p.name,
			Name:     instance.ID,
			Labels:   labelsFromEC2Tags(instance.Tags),
		}
	}

	p.state.Store(next)
	return nil
}

func (p *EC2Provider) resetRunState() {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.started = false
	p.cancel = nil
}

func labelsFromEC2Tags(tags map[string]string) map[string]string {
	labels := make(map[string]string, len(tags))
	for key, value := range tags {
		if strings.HasPrefix(key, "aegis/") {
			labels[key] = value
			continue
		}
		labels["ec2.tag/"+key] = value
	}

	return labels
}

func cloneEC2Filters(filters []EC2TagFilter) []EC2TagFilter {
	if len(filters) == 0 {
		return nil
	}

	cloned := make([]EC2TagFilter, len(filters))
	for i, filter := range filters {
		cloned[i] = EC2TagFilter{
			Key:    filter.Key,
			Values: append([]string(nil), filter.Values...),
		}
	}

	return cloned
}
