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

	"github.com/aws/aws-sdk-go-v2/aws"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/rest"

	"github.com/moolen/aegis/internal/config"
)

func TestExportedNewKubernetesRuntimeProviderUsesInjectedDefaults(t *testing.T) {
	originalLoadKubeconfig := loadKubeconfig
	originalNewKubernetesPodSource := newKubernetesPodSource
	originalNewKubernetesProvider := newKubernetesProvider
	t.Cleanup(func() {
		loadKubeconfig = originalLoadKubeconfig
		newKubernetesPodSource = originalNewKubernetesPodSource
		newKubernetesProvider = originalNewKubernetesProvider
	})

	restCfg := &rest.Config{Host: "https://cluster-a"}
	source := &fakeRuntimePodSource{}
	resolver := &fakeRuntimeResolver{}
	var loadedPath string
	var loadedContext string
	var sourceConfig *rest.Config
	var providerCfg KubernetesProviderConfig
	loadKubeconfig = func(kubeconfig string, kubeContext string) (*rest.Config, error) {
		loadedPath = kubeconfig
		loadedContext = kubeContext
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
		Name: "cluster-a",
		Auth: config.KubernetesAuthConfig{
			Provider:   "kubeconfig",
			Kubeconfig: "/tmp/a.kubeconfig",
			Context:    "dev",
		},
		Namespaces: []string{"default"},
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewKubernetesRuntimeProvider() error = %v", err)
	}
	if loadedPath != "/tmp/a.kubeconfig" {
		t.Fatalf("loaded kubeconfig = %q, want /tmp/a.kubeconfig", loadedPath)
	}
	if loadedContext != "dev" {
		t.Fatalf("loaded kubeconfig context = %q, want dev", loadedContext)
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
	originalLoadKubeconfig := loadKubeconfig
	originalNewKubernetesPodSource := newKubernetesPodSource
	originalNewKubernetesProvider := newKubernetesProvider
	t.Cleanup(func() {
		loadKubeconfig = originalLoadKubeconfig
		newKubernetesPodSource = originalNewKubernetesPodSource
		newKubernetesProvider = originalNewKubernetesProvider
	})

	explicitResync := 15 * time.Second
	var loadedPath string
	var providerCfg KubernetesProviderConfig
	loadKubeconfig = func(kubeconfig string, kubeContext string) (*rest.Config, error) {
		loadedPath = kubeconfig
		if kubeContext != "dev" {
			t.Fatalf("loadKubeconfig context = %q, want dev", kubeContext)
		}
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
		Name: "cluster-a",
		Auth: config.KubernetesAuthConfig{
			Provider:   "kubeconfig",
			Kubeconfig: "/tmp/a.kubeconfig",
			Context:    "dev",
		},
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

func TestNewKubernetesRuntimeProviderBuildsInClusterConfigFromAuthProvider(t *testing.T) {
	_, err := newKubernetesRuntimeProvider(config.KubernetesDiscoveryConfig{
		Name: "cluster-a",
		Auth: config.KubernetesAuthConfig{
			Provider: "inCluster",
		},
	}, slog.New(slog.NewTextHandler(io.Discard, nil)), kubernetesRuntimeProviderDeps{
		authDeps: kubernetesAuthDeps{
			loadInCluster: func() (*rest.Config, error) {
				return &rest.Config{}, nil
			},
		},
		newKubernetesPodSource: func(*rest.Config) (KubernetesPodSource, error) {
			return fakeRuntimePodSource{}, nil
		},
		newKubernetesProvider: func(KubernetesProviderConfig, *slog.Logger) (StartableResolver, error) {
			return &fakeRuntimeResolver{}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewKubernetesRuntimeProvider() error = %v", err)
	}
}

func TestNewKubernetesRuntimeProviderPropagatesLoadRESTConfigErrors(t *testing.T) {
	loadErr := errors.New("missing credentials")
	_, err := newKubernetesRuntimeProvider(config.KubernetesDiscoveryConfig{
		Name: "cluster-a",
		Auth: config.KubernetesAuthConfig{
			Provider: "inCluster",
		},
	}, slog.New(slog.NewTextHandler(io.Discard, nil)), kubernetesRuntimeProviderDeps{
		authDeps: kubernetesAuthDeps{
			loadInCluster: func() (*rest.Config, error) {
				return nil, loadErr
			},
		},
		newKubernetesPodSource: func(*rest.Config) (KubernetesPodSource, error) {
			t.Fatal("newKubernetesPodSource should not be called when rest config load fails")
			return nil, nil
		},
		newKubernetesProvider: func(KubernetesProviderConfig, *slog.Logger) (StartableResolver, error) {
			t.Fatal("newKubernetesProvider should not be called when rest config load fails")
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
	_, err := newKubernetesRuntimeProvider(config.KubernetesDiscoveryConfig{
		Name: "cluster-a",
		Auth: config.KubernetesAuthConfig{
			Provider: "inCluster",
		},
	}, slog.New(slog.NewTextHandler(io.Discard, nil)), kubernetesRuntimeProviderDeps{
		authDeps: kubernetesAuthDeps{
			loadInCluster: func() (*rest.Config, error) {
				return &rest.Config{}, nil
			},
		},
		newKubernetesPodSource: func(*rest.Config) (KubernetesPodSource, error) {
			return nil, errors.New("no cluster")
		},
		newKubernetesProvider: func(KubernetesProviderConfig, *slog.Logger) (StartableResolver, error) {
			t.Fatal("newKubernetesProvider should not be called when pod source construction fails")
			return nil, nil
		},
	})
	if err == nil {
		t.Fatal("expected construction error")
	}
}

func TestNewKubernetesRuntimeProviderPropagatesProviderErrors(t *testing.T) {
	providerErr := errors.New("provider init failed")
	_, err := newKubernetesRuntimeProvider(config.KubernetesDiscoveryConfig{
		Name: "cluster-a",
		Auth: config.KubernetesAuthConfig{
			Provider: "inCluster",
		},
	}, slog.New(slog.NewTextHandler(io.Discard, nil)), kubernetesRuntimeProviderDeps{
		authDeps: kubernetesAuthDeps{
			loadInCluster: func() (*rest.Config, error) {
				return &rest.Config{}, nil
			},
		},
		newKubernetesPodSource: func(*rest.Config) (KubernetesPodSource, error) {
			return fakeRuntimePodSource{}, nil
		},
		newKubernetesProvider: func(KubernetesProviderConfig, *slog.Logger) (StartableResolver, error) {
			return nil, providerErr
		},
	})
	if err == nil {
		t.Fatal("expected construction error")
	}
	if !errors.Is(err, providerErr) {
		t.Fatalf("error = %v, want wrapped provider error", err)
	}
}

func TestExportedNewEC2RuntimeProviderUsesInjectedDefaults(t *testing.T) {
	originalLoadAWSConfig := loadAWSConfig
	originalNewEC2Source := newEC2Source
	originalNewEC2Provider := newEC2Provider
	t.Cleanup(func() {
		loadAWSConfig = originalLoadAWSConfig
		newEC2Source = originalNewEC2Source
		newEC2Provider = originalNewEC2Provider
	})

	awsCfg := aws.Config{Region: "eu-central-1"}
	source := &fakeRuntimeEC2Source{}
	resolver := &fakeRuntimeResolver{}
	var loadedRegion string
	var sourceConfig aws.Config
	var providerCfg EC2ProviderConfig
	loadAWSConfig = func(ctx context.Context, region string) (aws.Config, error) {
		loadedRegion = region
		return awsCfg, nil
	}
	newEC2Source = func(cfg aws.Config) (EC2InstanceSource, error) {
		sourceConfig = cfg
		return source, nil
	}
	newEC2Provider = func(cfg EC2ProviderConfig, logger *slog.Logger) (StartableResolver, error) {
		providerCfg = cfg
		return resolver, nil
	}

	handle, err := NewEC2RuntimeProvider(config.EC2DiscoveryConfig{
		Name:   "production-ec2",
		Region: "eu-central-1",
		TagFilters: []config.EC2TagFilterConfig{{
			Key:    "aegis-managed",
			Values: []string{"true"},
		}},
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewEC2RuntimeProvider() error = %v", err)
	}
	if loadedRegion != "eu-central-1" {
		t.Fatalf("loaded region = %q, want eu-central-1", loadedRegion)
	}
	if sourceConfig.Region != awsCfg.Region {
		t.Fatalf("newEC2Source() region = %q, want %q", sourceConfig.Region, awsCfg.Region)
	}
	if handle.Name != "production-ec2" || handle.Kind != "ec2" {
		t.Fatalf("handle = %#v, want ec2/production-ec2", handle)
	}
	if providerCfg.Name != "production-ec2" {
		t.Fatalf("provider config name = %q, want production-ec2", providerCfg.Name)
	}
	if providerCfg.Source != source {
		t.Fatalf("provider config source = %p, want %p", providerCfg.Source, source)
	}
	if providerCfg.PollInterval != 30*time.Second {
		t.Fatalf("provider config poll interval = %s, want %s", providerCfg.PollInterval, 30*time.Second)
	}
	if len(providerCfg.TagFilters) != 1 || providerCfg.TagFilters[0].Key != "aegis-managed" {
		t.Fatalf("provider config tag filters = %#v, want aegis-managed filter", providerCfg.TagFilters)
	}
	if handle.Provider != resolver {
		t.Fatalf("handle provider = %p, want %p", handle.Provider, resolver)
	}
}

func TestExportedNewEC2RuntimeProviderForwardsExplicitPollInterval(t *testing.T) {
	originalLoadAWSConfig := loadAWSConfig
	originalNewEC2Source := newEC2Source
	originalNewEC2Provider := newEC2Provider
	t.Cleanup(func() {
		loadAWSConfig = originalLoadAWSConfig
		newEC2Source = originalNewEC2Source
		newEC2Provider = originalNewEC2Provider
	})

	explicitPollInterval := 15 * time.Second
	var providerCfg EC2ProviderConfig
	loadAWSConfig = func(context.Context, string) (aws.Config, error) {
		return aws.Config{Region: "eu-central-1"}, nil
	}
	newEC2Source = func(aws.Config) (EC2InstanceSource, error) {
		return &fakeRuntimeEC2Source{}, nil
	}
	newEC2Provider = func(cfg EC2ProviderConfig, logger *slog.Logger) (StartableResolver, error) {
		providerCfg = cfg
		return &fakeRuntimeResolver{}, nil
	}

	handle, err := NewEC2RuntimeProvider(config.EC2DiscoveryConfig{
		Name:         "production-ec2",
		Region:       "eu-central-1",
		PollInterval: &explicitPollInterval,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewEC2RuntimeProvider() error = %v", err)
	}
	if handle.Name != "production-ec2" || handle.Kind != "ec2" {
		t.Fatalf("handle = %#v, want ec2/production-ec2", handle)
	}
	if providerCfg.PollInterval != explicitPollInterval {
		t.Fatalf("provider config poll interval = %s, want %s", providerCfg.PollInterval, explicitPollInterval)
	}
}

func TestNewEC2RuntimeProviderPropagatesLoadAWSConfigErrors(t *testing.T) {
	loadErr := errors.New("missing credentials")
	_, err := newEC2RuntimeProvider(config.EC2DiscoveryConfig{Name: "production-ec2", Region: "eu-central-1"}, slog.New(slog.NewTextHandler(io.Discard, nil)), ec2RuntimeProviderDeps{
		loadAWSConfig: func(context.Context, string) (aws.Config, error) {
			return aws.Config{}, loadErr
		},
		newEC2Source: func(aws.Config) (EC2InstanceSource, error) {
			t.Fatal("newEC2Source should not be called when aws config load fails")
			return nil, nil
		},
		newEC2Provider: func(EC2ProviderConfig, *slog.Logger) (StartableResolver, error) {
			t.Fatal("newEC2Provider should not be called when aws config load fails")
			return nil, nil
		},
	})
	if err == nil {
		t.Fatal("expected construction error")
	}
	if !errors.Is(err, loadErr) {
		t.Fatalf("error = %v, want wrapped load error", err)
	}
	if !strings.Contains(err.Error(), "load aws config for production-ec2") {
		t.Fatalf("error = %q, want contextual load message", err)
	}
}

func TestNewEC2RuntimeProviderPropagatesSourceErrors(t *testing.T) {
	_, err := newEC2RuntimeProvider(config.EC2DiscoveryConfig{Name: "production-ec2", Region: "eu-central-1"}, slog.New(slog.NewTextHandler(io.Discard, nil)), ec2RuntimeProviderDeps{
		loadAWSConfig: func(context.Context, string) (aws.Config, error) {
			return aws.Config{Region: "eu-central-1"}, nil
		},
		newEC2Source: func(aws.Config) (EC2InstanceSource, error) {
			return nil, errors.New("no ec2 client")
		},
		newEC2Provider: func(EC2ProviderConfig, *slog.Logger) (StartableResolver, error) {
			t.Fatal("newEC2Provider should not be called when ec2 source construction fails")
			return nil, nil
		},
	})
	if err == nil {
		t.Fatal("expected construction error")
	}
}

func TestNewEC2RuntimeProviderPropagatesProviderErrors(t *testing.T) {
	providerErr := errors.New("provider init failed")
	_, err := newEC2RuntimeProvider(config.EC2DiscoveryConfig{Name: "production-ec2", Region: "eu-central-1"}, slog.New(slog.NewTextHandler(io.Discard, nil)), ec2RuntimeProviderDeps{
		loadAWSConfig: func(context.Context, string) (aws.Config, error) {
			return aws.Config{Region: "eu-central-1"}, nil
		},
		newEC2Source: func(aws.Config) (EC2InstanceSource, error) {
			return &fakeRuntimeEC2Source{}, nil
		},
		newEC2Provider: func(EC2ProviderConfig, *slog.Logger) (StartableResolver, error) {
			return nil, providerErr
		},
	})
	if err == nil {
		t.Fatal("expected construction error")
	}
	if !errors.Is(err, providerErr) {
		t.Fatalf("error = %v, want wrapped provider error", err)
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

func (*fakeRuntimeResolver) Start(context.Context, time.Duration) error {
	return nil
}

func (*fakeRuntimeResolver) Resolve(net.IP) (*Identity, error) {
	return nil, nil
}

type fakeRuntimeEC2Source struct{}

func (*fakeRuntimeEC2Source) Instances(context.Context, []EC2TagFilter) ([]EC2Instance, error) {
	return nil, nil
}
