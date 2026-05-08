package identity

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/moolen/aegis/internal/config"
)

func TestDiscoveryRuntimeStartReturnsNilWhenDiscoveryNotConfigured(t *testing.T) {
	runtime := NewDiscoveryRuntime(config.DiscoveryConfig{}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)

	resolver, err := runtime.Start(context.Background())
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if resolver != nil {
		t.Fatalf("Start() resolver = %#v, want nil", resolver)
	}
}

func TestDiscoveryRuntimeStartBuildsAndStartsConfiguredProvidersInOrder(t *testing.T) {
	kubeResolver := &trackingStartableResolver{}
	ec2Resolver := &trackingStartableResolver{}
	var started []string

	runtime := newDiscoveryRuntime(
		config.DiscoveryConfig{
			Kubernetes: []config.KubernetesDiscoveryConfig{{Name: "cluster-a"}},
			EC2:        []config.EC2DiscoveryConfig{{Name: "production-ec2"}},
		},
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		nil,
		discoveryRuntimeDeps{
			startupTimeout: 5 * time.Second,
			newKubernetesRuntimeProvider: func(cfg config.KubernetesDiscoveryConfig, logger *slog.Logger) (RuntimeProvider, error) {
				return RuntimeProvider{Name: cfg.Name, Kind: "kubernetes", Provider: &trackingStartableResolver{
					onStart: func(timeout time.Duration) {
						started = append(started, "kubernetes:"+cfg.Name)
						if timeout != 5*time.Second {
							t.Fatalf("kubernetes startup timeout = %s, want %s", timeout, 5*time.Second)
						}
					},
					resolveIdentity: kubeResolver.resolveIdentity,
				}}, nil
			},
			newEC2RuntimeProvider: func(cfg config.EC2DiscoveryConfig, logger *slog.Logger) (RuntimeProvider, error) {
				return RuntimeProvider{Name: cfg.Name, Kind: "ec2", Provider: &trackingStartableResolver{
					onStart: func(timeout time.Duration) {
						started = append(started, "ec2:"+cfg.Name)
						if timeout != 5*time.Second {
							t.Fatalf("ec2 startup timeout = %s, want %s", timeout, 5*time.Second)
						}
					},
					resolveIdentity: ec2Resolver.resolveIdentity,
				}}, nil
			},
		},
	)

	resolver, err := runtime.Start(context.Background())
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if resolver == nil {
		t.Fatal("Start() resolver = nil, want composite resolver")
	}

	statuses := resolver.ProviderStatuses()
	if len(statuses) != 2 {
		t.Fatalf("provider statuses = %#v, want 2 active providers", statuses)
	}
	if statuses[0].Name != "cluster-a" || statuses[0].Kind != "kubernetes" {
		t.Fatalf("provider statuses[0] = %#v, want cluster-a/kubernetes", statuses[0])
	}
	if statuses[1].Name != "production-ec2" || statuses[1].Kind != "ec2" {
		t.Fatalf("provider statuses[1] = %#v, want production-ec2/ec2", statuses[1])
	}
	if len(started) != 2 || started[0] != "kubernetes:cluster-a" || started[1] != "ec2:production-ec2" {
		t.Fatalf("start order = %#v, want kubernetes then ec2", started)
	}
}

func TestDiscoveryRuntimeStartSkipsProviderBuildAndStartFailures(t *testing.T) {
	goodResolver := &trackingStartableResolver{}
	runtime := newDiscoveryRuntime(
		config.DiscoveryConfig{
			Kubernetes: []config.KubernetesDiscoveryConfig{{Name: "broken-build"}, {Name: "cluster-a"}},
			EC2:        []config.EC2DiscoveryConfig{{Name: "broken-start"}, {Name: "production-ec2"}},
		},
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		nil,
		discoveryRuntimeDeps{
			startupTimeout: time.Second,
			newKubernetesRuntimeProvider: func(cfg config.KubernetesDiscoveryConfig, logger *slog.Logger) (RuntimeProvider, error) {
				if cfg.Name == "broken-build" {
					return RuntimeProvider{}, errors.New("build failed")
				}
				return RuntimeProvider{Name: cfg.Name, Kind: "kubernetes", Provider: goodResolver}, nil
			},
			newEC2RuntimeProvider: func(cfg config.EC2DiscoveryConfig, logger *slog.Logger) (RuntimeProvider, error) {
				if cfg.Name == "broken-start" {
					return RuntimeProvider{Name: cfg.Name, Kind: "ec2", Provider: &trackingStartableResolver{startErr: errors.New("start failed")}}, nil
				}
				return RuntimeProvider{Name: cfg.Name, Kind: "ec2", Provider: goodResolver}, nil
			},
		},
	)

	resolver, err := runtime.Start(context.Background())
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if resolver == nil {
		t.Fatal("Start() resolver = nil, want active providers")
	}

	statuses := resolver.ProviderStatuses()
	if len(statuses) != 2 {
		t.Fatalf("provider statuses = %#v, want only successfully started providers", statuses)
	}
	if statuses[0].Name != "cluster-a" || statuses[1].Name != "production-ec2" {
		t.Fatalf("provider order = %#v, want surviving providers in config order", statuses)
	}
}

func TestDiscoveryRuntimeStartErrorsWhenConfiguredProvidersDoNotBecomeActive(t *testing.T) {
	runtime := newDiscoveryRuntime(
		config.DiscoveryConfig{
			Kubernetes: []config.KubernetesDiscoveryConfig{{Name: "cluster-a"}},
			EC2:        []config.EC2DiscoveryConfig{{Name: "production-ec2"}},
		},
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		nil,
		discoveryRuntimeDeps{
			startupTimeout: time.Second,
			newKubernetesRuntimeProvider: func(cfg config.KubernetesDiscoveryConfig, logger *slog.Logger) (RuntimeProvider, error) {
				return RuntimeProvider{}, errors.New("build failed")
			},
			newEC2RuntimeProvider: func(cfg config.EC2DiscoveryConfig, logger *slog.Logger) (RuntimeProvider, error) {
				return RuntimeProvider{Name: cfg.Name, Kind: "ec2", Provider: &trackingStartableResolver{startErr: errors.New("start failed")}}, nil
			},
		},
	)

	resolver, err := runtime.Start(context.Background())
	if err == nil {
		t.Fatal("Start() error = nil, want configured-but-inactive error")
	}
	if err.Error() != "discovery configured but no providers became active" {
		t.Fatalf("Start() error = %q, want configured-but-inactive error", err)
	}
	if resolver != nil {
		t.Fatalf("Start() resolver = %#v, want nil on error", resolver)
	}
}

type trackingStartableResolver struct {
	startErr        error
	onStart         func(time.Duration)
	resolveIdentity func(net.IP) (*Identity, error)
}

func (r *trackingStartableResolver) Start(_ context.Context, timeout time.Duration) error {
	if r.onStart != nil {
		r.onStart(timeout)
	}
	return r.startErr
}

func (r *trackingStartableResolver) Resolve(ip net.IP) (*Identity, error) {
	if r.resolveIdentity != nil {
		return r.resolveIdentity(ip)
	}
	return nil, nil
}
