package identity

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"k8s.io/client-go/kubernetes"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/moolen/aegis/internal/config"
)

type StartableResolver interface {
	Start(context.Context) error
	Resolve(net.IP) (*Identity, error)
}

type kubernetesRuntimeProviderDeps struct {
	loadRESTConfig         func(string) (*rest.Config, error)
	newKubernetesPodSource func(*rest.Config) (KubernetesPodSource, error)
}

var loadRESTConfig = func(kubeconfig string) (*rest.Config, error) {
	if kubeconfig != "" {
		return clientcmd.BuildConfigFromFlags("", kubeconfig)
	}
	return rest.InClusterConfig()
}

var newKubernetesPodSource = func(restCfg *rest.Config) (KubernetesPodSource, error) {
	clientset, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return nil, err
	}

	return coreV1PodSource{client: clientset.CoreV1()}, nil
}

func defaultKubernetesRuntimeProviderDeps() kubernetesRuntimeProviderDeps {
	return kubernetesRuntimeProviderDeps{
		loadRESTConfig:         loadRESTConfig,
		newKubernetesPodSource: newKubernetesPodSource,
	}
}

type RuntimeProvider struct {
	Name     string
	Kind     string
	Provider StartableResolver
}

type coreV1PodSource struct {
	client corev1.CoreV1Interface
}

func (s coreV1PodSource) Pods(namespace string) KubernetesPodNamespaceClient {
	return s.client.Pods(namespace)
}

func NewKubernetesRuntimeProvider(cfg config.KubernetesDiscoveryConfig, logger *slog.Logger) (RuntimeProvider, error) {
	resyncPeriod := time.Minute
	if cfg.ResyncPeriod != nil {
		resyncPeriod = *cfg.ResyncPeriod
	}

	cfg.ResyncPeriod = &resyncPeriod
	return newKubernetesRuntimeProvider(cfg, logger, defaultKubernetesRuntimeProviderDeps())
}

func newKubernetesRuntimeProvider(cfg config.KubernetesDiscoveryConfig, logger *slog.Logger, deps kubernetesRuntimeProviderDeps) (RuntimeProvider, error) {
	restCfg, err := deps.loadRESTConfig(cfg.Kubeconfig)
	if err != nil {
		return RuntimeProvider{}, fmt.Errorf("load kubernetes rest config for %s: %w", cfg.Name, err)
	}

	source, err := deps.newKubernetesPodSource(restCfg)
	if err != nil {
		return RuntimeProvider{}, fmt.Errorf("build kubernetes pod source for %s: %w", cfg.Name, err)
	}

	var resyncPeriod time.Duration
	if cfg.ResyncPeriod != nil {
		resyncPeriod = *cfg.ResyncPeriod
	}

	provider, err := NewKubernetesProvider(KubernetesProviderConfig{
		Name:         cfg.Name,
		Source:       source,
		Namespaces:   cfg.Namespaces,
		ResyncPeriod: resyncPeriod,
	}, logger)
	if err != nil {
		return RuntimeProvider{}, err
	}

	return RuntimeProvider{
		Name:     cfg.Name,
		Kind:     "kubernetes",
		Provider: provider,
	}, nil
}
