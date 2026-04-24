package identity

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/rest"

	"github.com/moolen/aegis/internal/config"
)

func TestExportedNewKubernetesRuntimeProviderUsesInjectedDefaults(t *testing.T) {
	originalLoadRESTConfig := loadRESTConfig
	originalNewKubernetesPodSource := newKubernetesPodSource
	originalNewKubernetesProvider := newKubernetesProvider
	t.Cleanup(func() {
		loadRESTConfig = originalLoadRESTConfig
		newKubernetesPodSource = originalNewKubernetesPodSource
		newKubernetesProvider = originalNewKubernetesProvider
	})

	restCfg := &rest.Config{Host: "https://cluster-a"}
	source := &fakeRuntimePodSource{}
	resolver := &fakeRuntimeResolver{}
	var loadedPath string
	var sourceConfig *rest.Config
	var providerCfg KubernetesProviderConfig
	loadRESTConfig = func(kubeconfig string) (*rest.Config, error) {
		loadedPath = kubeconfig
		return restCfg, nil
	}
	newKubernetesPodSource = func(cfg *rest.Config) (KubernetesPodSource, error) {
		sourceConfig = cfg
		return source, nil
	}
	newKubernetesProvider = func(cfg KubernetesProviderConfig, logger *slog.Logger) (StartableResolver, error) {
		providerCfg = cfg
		return resolver, nil
	}

	handle, err := NewKubernetesRuntimeProvider(config.KubernetesDiscoveryConfig{
		Name:       "cluster-a",
		Kubeconfig: "/tmp/a.kubeconfig",
		Namespaces: []string{"default"},
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewKubernetesRuntimeProvider() error = %v", err)
	}
	if loadedPath != "/tmp/a.kubeconfig" {
		t.Fatalf("loaded kubeconfig = %q, want /tmp/a.kubeconfig", loadedPath)
	}
	if sourceConfig != restCfg {
		t.Fatalf("newKubernetesPodSource() config = %p, want %p", sourceConfig, restCfg)
	}
	if handle.Name != "cluster-a" || handle.Kind != "kubernetes" {
		t.Fatalf("handle = %#v, want kubernetes/cluster-a", handle)
	}
	if providerCfg.Name != "cluster-a" {
		t.Fatalf("provider config name = %q, want cluster-a", providerCfg.Name)
	}
	if providerCfg.Source != source {
		t.Fatalf("provider config source = %p, want %p", providerCfg.Source, source)
	}
	if len(providerCfg.Namespaces) != 1 || providerCfg.Namespaces[0] != "default" {
		t.Fatalf("provider config namespaces = %#v, want []string{\"default\"}", providerCfg.Namespaces)
	}
	if providerCfg.ResyncPeriod != time.Minute {
		t.Fatalf("provider config resync = %s, want %s", providerCfg.ResyncPeriod, time.Minute)
	}
	if handle.Provider != resolver {
		t.Fatalf("handle provider = %p, want %p", handle.Provider, resolver)
	}
}

func TestExportedNewKubernetesRuntimeProviderForwardsExplicitResyncPeriod(t *testing.T) {
	originalLoadRESTConfig := loadRESTConfig
	originalNewKubernetesPodSource := newKubernetesPodSource
	originalNewKubernetesProvider := newKubernetesProvider
	t.Cleanup(func() {
		loadRESTConfig = originalLoadRESTConfig
		newKubernetesPodSource = originalNewKubernetesPodSource
		newKubernetesProvider = originalNewKubernetesProvider
	})

	explicitResync := 15 * time.Second
	var loadedPath string
	var providerCfg KubernetesProviderConfig
	loadRESTConfig = func(kubeconfig string) (*rest.Config, error) {
		loadedPath = kubeconfig
		return &rest.Config{}, nil
	}
	newKubernetesPodSource = func(*rest.Config) (KubernetesPodSource, error) {
		return fakeRuntimePodSource{}, nil
	}
	newKubernetesProvider = func(cfg KubernetesProviderConfig, logger *slog.Logger) (StartableResolver, error) {
		providerCfg = cfg
		return &KubernetesProvider{}, nil
	}

	handle, err := NewKubernetesRuntimeProvider(config.KubernetesDiscoveryConfig{
		Name:         "cluster-a",
		Kubeconfig:   "/tmp/a.kubeconfig",
		Namespaces:   []string{"default"},
		ResyncPeriod: &explicitResync,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewKubernetesRuntimeProvider() error = %v", err)
	}
	if loadedPath != "/tmp/a.kubeconfig" {
		t.Fatalf("loaded kubeconfig = %q, want /tmp/a.kubeconfig", loadedPath)
	}
	if handle.Name != "cluster-a" || handle.Kind != "kubernetes" {
		t.Fatalf("handle = %#v, want kubernetes/cluster-a", handle)
	}
	if providerCfg.ResyncPeriod != explicitResync {
		t.Fatalf("provider config resync = %s, want %s", providerCfg.ResyncPeriod, explicitResync)
	}
}

func TestNewKubernetesRuntimeProviderFallsBackToInClusterConfig(t *testing.T) {
	_, err := newKubernetesRuntimeProvider(config.KubernetesDiscoveryConfig{Name: "cluster-a"}, slog.New(slog.NewTextHandler(io.Discard, nil)), kubernetesRuntimeProviderDeps{
		loadRESTConfig: func(kubeconfig string) (*rest.Config, error) {
			if kubeconfig != "" {
				t.Fatalf("loadRESTConfig kubeconfig = %q, want empty", kubeconfig)
			}
			return &rest.Config{}, nil
		},
		newKubernetesPodSource: func(*rest.Config) (KubernetesPodSource, error) {
			return fakeRuntimePodSource{}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewKubernetesRuntimeProvider() error = %v", err)
	}
}

func TestNewKubernetesRuntimeProviderPropagatesLoadRESTConfigErrors(t *testing.T) {
	loadErr := errors.New("missing credentials")
	_, err := newKubernetesRuntimeProvider(config.KubernetesDiscoveryConfig{Name: "cluster-a"}, slog.New(slog.NewTextHandler(io.Discard, nil)), kubernetesRuntimeProviderDeps{
		loadRESTConfig: func(string) (*rest.Config, error) {
			return nil, loadErr
		},
		newKubernetesPodSource: func(*rest.Config) (KubernetesPodSource, error) {
			t.Fatal("newKubernetesPodSource should not be called when rest config load fails")
			return nil, nil
		},
	})
	if err == nil {
		t.Fatal("expected construction error")
	}
	if !errors.Is(err, loadErr) {
		t.Fatalf("error = %v, want wrapped load error", err)
	}
	if !strings.Contains(err.Error(), "load kubernetes rest config for cluster-a") {
		t.Fatalf("error = %q, want contextual load message", err)
	}
}

func TestNewKubernetesRuntimeProviderPropagatesSourceErrors(t *testing.T) {
	_, err := newKubernetesRuntimeProvider(config.KubernetesDiscoveryConfig{Name: "cluster-a"}, slog.New(slog.NewTextHandler(io.Discard, nil)), kubernetesRuntimeProviderDeps{
		loadRESTConfig: func(string) (*rest.Config, error) {
			return &rest.Config{}, nil
		},
		newKubernetesPodSource: func(*rest.Config) (KubernetesPodSource, error) {
			return nil, errors.New("no cluster")
		},
	})
	if err == nil {
		t.Fatal("expected construction error")
	}
}

type fakeRuntimePodSource struct{}

func (fakeRuntimePodSource) Pods(string) KubernetesPodNamespaceClient {
	return fakeRuntimeNamespaceClient{}
}

type fakeRuntimeNamespaceClient struct{}

func (fakeRuntimeNamespaceClient) List(context.Context, metav1.ListOptions) (*corev1.PodList, error) {
	return &corev1.PodList{}, nil
}

func (fakeRuntimeNamespaceClient) Watch(context.Context, metav1.ListOptions) (watch.Interface, error) {
	return watch.NewRaceFreeFake(), nil
}

type fakeRuntimeResolver struct{}

func (*fakeRuntimeResolver) Start(context.Context) error {
	return nil
}

func (*fakeRuntimeResolver) Resolve(net.IP) (*Identity, error) {
	return nil, nil
}
