package identity

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/rest"

	"github.com/moolen/aegis/internal/config"
)

func TestNewKubernetesRuntimeProviderUsesExplicitKubeconfig(t *testing.T) {
	restoreLoad := loadRESTConfig
	restoreSource := newKubernetesPodSource
	t.Cleanup(func() {
		loadRESTConfig = restoreLoad
		newKubernetesPodSource = restoreSource
	})

	var loadedPath string
	loadRESTConfig = func(kubeconfig string) (*rest.Config, error) {
		loadedPath = kubeconfig
		return &rest.Config{}, nil
	}
	newKubernetesPodSource = func(*rest.Config) (KubernetesPodSource, error) {
		return fakeRuntimePodSource{}, nil
	}

	handle, err := NewKubernetesRuntimeProvider(config.KubernetesDiscoveryConfig{
		Name:         "cluster-a",
		Kubeconfig:   "/tmp/a.kubeconfig",
		Namespaces:   []string{"default"},
		ResyncPeriod: func() *time.Duration { d := 15 * time.Second; return &d }(),
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
}

func TestNewKubernetesRuntimeProviderFallsBackToInClusterConfig(t *testing.T) {
	restoreLoad := loadRESTConfig
	restoreSource := newKubernetesPodSource
	t.Cleanup(func() {
		loadRESTConfig = restoreLoad
		newKubernetesPodSource = restoreSource
	})

	loadRESTConfig = func(kubeconfig string) (*rest.Config, error) {
		if kubeconfig != "" {
			t.Fatalf("loadRESTConfig kubeconfig = %q, want empty", kubeconfig)
		}
		return &rest.Config{}, nil
	}
	newKubernetesPodSource = func(*rest.Config) (KubernetesPodSource, error) {
		return fakeRuntimePodSource{}, nil
	}

	_, err := NewKubernetesRuntimeProvider(config.KubernetesDiscoveryConfig{Name: "cluster-a"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewKubernetesRuntimeProvider() error = %v", err)
	}
}

func TestNewKubernetesRuntimeProviderPropagatesSourceErrors(t *testing.T) {
	restoreLoad := loadRESTConfig
	restoreSource := newKubernetesPodSource
	t.Cleanup(func() {
		loadRESTConfig = restoreLoad
		newKubernetesPodSource = restoreSource
	})

	loadRESTConfig = func(string) (*rest.Config, error) {
		return &rest.Config{}, nil
	}
	newKubernetesPodSource = func(*rest.Config) (KubernetesPodSource, error) {
		return nil, errors.New("no cluster")
	}

	_, err := NewKubernetesRuntimeProvider(config.KubernetesDiscoveryConfig{Name: "cluster-a"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
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
