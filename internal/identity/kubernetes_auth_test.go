package identity

import (
	"context"
	"errors"
	"strings"
	"testing"

	"k8s.io/client-go/rest"

	"github.com/moolen/aegis/internal/config"
)

func TestBuildKubernetesRESTConfigForKubeconfig(t *testing.T) {
	expected := &rest.Config{Host: "https://cluster-a"}
	var gotPath string
	var gotContext string

	restCfg, err := buildKubernetesRESTConfig(context.Background(), config.KubernetesDiscoveryConfig{
		Name: "cluster-a",
		Auth: config.KubernetesAuthConfig{
			Provider:   "kubeconfig",
			Kubeconfig: "/tmp/a.kubeconfig",
			Context:    "dev",
		},
	}, kubernetesAuthDeps{
		loadKubeconfig: func(path string, kubeContext string) (*rest.Config, error) {
			gotPath = path
			gotContext = kubeContext
			return expected, nil
		},
	})
	if err != nil {
		t.Fatalf("buildKubernetesRESTConfig() error = %v", err)
	}
	if restCfg != expected {
		t.Fatalf("buildKubernetesRESTConfig() config = %p, want %p", restCfg, expected)
	}
	if gotPath != "/tmp/a.kubeconfig" {
		t.Fatalf("loadKubeconfig path = %q, want /tmp/a.kubeconfig", gotPath)
	}
	if gotContext != "dev" {
		t.Fatalf("loadKubeconfig context = %q, want dev", gotContext)
	}
}

func TestBuildKubernetesRESTConfigForInCluster(t *testing.T) {
	expected := &rest.Config{Host: "https://in-cluster"}

	restCfg, err := buildKubernetesRESTConfig(context.Background(), config.KubernetesDiscoveryConfig{
		Name: "cluster-a",
		Auth: config.KubernetesAuthConfig{
			Provider: "inCluster",
		},
	}, kubernetesAuthDeps{
		loadInCluster: func() (*rest.Config, error) {
			return expected, nil
		},
	})
	if err != nil {
		t.Fatalf("buildKubernetesRESTConfig() error = %v", err)
	}
	if restCfg != expected {
		t.Fatalf("buildKubernetesRESTConfig() config = %p, want %p", restCfg, expected)
	}
}

func TestBuildKubernetesRESTConfigForEKS(t *testing.T) {
	expected := &rest.Config{Host: "https://eks"}
	ctx := context.WithValue(context.Background(), struct{}{}, "ctx")
	var gotCtx context.Context
	var gotRegion string
	var gotClusterName string

	restCfg, err := buildKubernetesRESTConfig(ctx, config.KubernetesDiscoveryConfig{
		Name: "cluster-a",
		Auth: config.KubernetesAuthConfig{
			Provider:    "eks",
			Region:      "eu-central-1",
			ClusterName: "cluster-a",
		},
	}, kubernetesAuthDeps{
		loadEKS: func(ctx context.Context, region string, clusterName string) (*rest.Config, error) {
			gotCtx = ctx
			gotRegion = region
			gotClusterName = clusterName
			return expected, nil
		},
	})
	if err != nil {
		t.Fatalf("buildKubernetesRESTConfig() error = %v", err)
	}
	if restCfg != expected {
		t.Fatalf("buildKubernetesRESTConfig() config = %p, want %p", restCfg, expected)
	}
	if gotCtx != ctx {
		t.Fatal("loadEKS context was not forwarded")
	}
	if gotRegion != "eu-central-1" {
		t.Fatalf("loadEKS region = %q, want eu-central-1", gotRegion)
	}
	if gotClusterName != "cluster-a" {
		t.Fatalf("loadEKS clusterName = %q, want cluster-a", gotClusterName)
	}
}

func TestBuildKubernetesRESTConfigForGKE(t *testing.T) {
	expected := &rest.Config{Host: "https://gke"}
	ctx := context.WithValue(context.Background(), struct{}{}, "ctx")
	var gotCtx context.Context
	var gotProject string
	var gotLocation string
	var gotClusterName string

	restCfg, err := buildKubernetesRESTConfig(ctx, config.KubernetesDiscoveryConfig{
		Name: "cluster-b",
		Auth: config.KubernetesAuthConfig{
			Provider:    "gke",
			Project:     "prod-project",
			Location:    "europe-west1",
			ClusterName: "cluster-b",
		},
	}, kubernetesAuthDeps{
		loadGKE: func(ctx context.Context, project string, location string, clusterName string) (*rest.Config, error) {
			gotCtx = ctx
			gotProject = project
			gotLocation = location
			gotClusterName = clusterName
			return expected, nil
		},
	})
	if err != nil {
		t.Fatalf("buildKubernetesRESTConfig() error = %v", err)
	}
	if restCfg != expected {
		t.Fatalf("buildKubernetesRESTConfig() config = %p, want %p", restCfg, expected)
	}
	if gotCtx != ctx {
		t.Fatal("loadGKE context was not forwarded")
	}
	if gotProject != "prod-project" {
		t.Fatalf("loadGKE project = %q, want prod-project", gotProject)
	}
	if gotLocation != "europe-west1" {
		t.Fatalf("loadGKE location = %q, want europe-west1", gotLocation)
	}
	if gotClusterName != "cluster-b" {
		t.Fatalf("loadGKE clusterName = %q, want cluster-b", gotClusterName)
	}
}

func TestBuildKubernetesRESTConfigForAKS(t *testing.T) {
	expected := &rest.Config{Host: "https://aks"}
	ctx := context.WithValue(context.Background(), struct{}{}, "ctx")
	var gotCtx context.Context
	var gotSubscriptionID string
	var gotResourceGroup string
	var gotClusterName string

	restCfg, err := buildKubernetesRESTConfig(ctx, config.KubernetesDiscoveryConfig{
		Name: "cluster-c",
		Auth: config.KubernetesAuthConfig{
			Provider:       "aks",
			SubscriptionID: "sub-123",
			ResourceGroup:  "rg-platform",
			ClusterName:    "cluster-c",
		},
	}, kubernetesAuthDeps{
		loadAKS: func(ctx context.Context, subscriptionID string, resourceGroup string, clusterName string) (*rest.Config, error) {
			gotCtx = ctx
			gotSubscriptionID = subscriptionID
			gotResourceGroup = resourceGroup
			gotClusterName = clusterName
			return expected, nil
		},
	})
	if err != nil {
		t.Fatalf("buildKubernetesRESTConfig() error = %v", err)
	}
	if restCfg != expected {
		t.Fatalf("buildKubernetesRESTConfig() config = %p, want %p", restCfg, expected)
	}
	if gotCtx != ctx {
		t.Fatal("loadAKS context was not forwarded")
	}
	if gotSubscriptionID != "sub-123" {
		t.Fatalf("loadAKS subscriptionID = %q, want sub-123", gotSubscriptionID)
	}
	if gotResourceGroup != "rg-platform" {
		t.Fatalf("loadAKS resourceGroup = %q, want rg-platform", gotResourceGroup)
	}
	if gotClusterName != "cluster-c" {
		t.Fatalf("loadAKS clusterName = %q, want cluster-c", gotClusterName)
	}
}

func TestBuildKubernetesRESTConfigRejectsUnknownAuthProvider(t *testing.T) {
	_, err := buildKubernetesRESTConfig(context.Background(), config.KubernetesDiscoveryConfig{
		Name: "cluster-a",
		Auth: config.KubernetesAuthConfig{
			Provider: "unknown",
		},
	}, kubernetesAuthDeps{})
	if err == nil {
		t.Fatal("expected unsupported provider error")
	}
	if !strings.Contains(err.Error(), `unsupported kubernetes auth provider "unknown"`) {
		t.Fatalf("error = %q, want unsupported provider message", err)
	}
}

func TestBuildKubernetesRESTConfigPropagatesLoaderErrors(t *testing.T) {
	loadErr := errors.New("missing credentials")

	_, err := buildKubernetesRESTConfig(context.Background(), config.KubernetesDiscoveryConfig{
		Name: "cluster-a",
		Auth: config.KubernetesAuthConfig{
			Provider: "inCluster",
		},
	}, kubernetesAuthDeps{
		loadInCluster: func() (*rest.Config, error) {
			return nil, loadErr
		},
	})
	if !errors.Is(err, loadErr) {
		t.Fatalf("error = %v, want wrapped loader error", err)
	}
}
