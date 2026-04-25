package identity

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	"github.com/moolen/aegis/internal/config"
)

type kubernetesAuthDeps struct {
	loadKubeconfig func(path string, context string) (*rest.Config, error)
	loadInCluster  func() (*rest.Config, error)
	loadEKS        func(ctx context.Context, region string, clusterName string) (*rest.Config, error)
	loadGKE        func(ctx context.Context, project string, location string, clusterName string) (*rest.Config, error)
	loadAKS        func(ctx context.Context, subscriptionID string, resourceGroup string, clusterName string) (*rest.Config, error)
}

var loadKubeconfig = defaultLoadKubeconfig
var loadInCluster = rest.InClusterConfig
var loadEKS = defaultLoadEKS
var loadGKE = defaultLoadGKE
var loadAKS = defaultLoadAKS

func defaultKubernetesAuthDeps() kubernetesAuthDeps {
	return kubernetesAuthDeps{
		loadKubeconfig: loadKubeconfig,
		loadInCluster:  loadInCluster,
		loadEKS:        loadEKS,
		loadGKE:        loadGKE,
		loadAKS:        loadAKS,
	}
}

func (d kubernetesAuthDeps) withDefaults() kubernetesAuthDeps {
	defaults := defaultKubernetesAuthDeps()
	if d.loadKubeconfig == nil {
		d.loadKubeconfig = defaults.loadKubeconfig
	}
	if d.loadInCluster == nil {
		d.loadInCluster = defaults.loadInCluster
	}
	if d.loadEKS == nil {
		d.loadEKS = defaults.loadEKS
	}
	if d.loadGKE == nil {
		d.loadGKE = defaults.loadGKE
	}
	if d.loadAKS == nil {
		d.loadAKS = defaults.loadAKS
	}
	return d
}

func buildKubernetesRESTConfig(ctx context.Context, cfg config.KubernetesDiscoveryConfig, deps kubernetesAuthDeps) (*rest.Config, error) {
	deps = deps.withDefaults()

	switch normalizeKubernetesAuthProvider(cfg.Auth.Provider) {
	case "kubeconfig":
		return deps.loadKubeconfig(cfg.Auth.Kubeconfig, cfg.Auth.Context)
	case "incluster":
		return deps.loadInCluster()
	case "eks":
		return deps.loadEKS(ctx, cfg.Auth.Region, cfg.Auth.ClusterName)
	case "gke":
		return deps.loadGKE(ctx, cfg.Auth.Project, cfg.Auth.Location, cfg.Auth.ClusterName)
	case "aks":
		return deps.loadAKS(ctx, cfg.Auth.SubscriptionID, cfg.Auth.ResourceGroup, cfg.Auth.ClusterName)
	default:
		return nil, fmt.Errorf("unsupported kubernetes auth provider %q", cfg.Auth.Provider)
	}
}

func defaultLoadKubeconfig(path string, kubeContext string) (*rest.Config, error) {
	loadingRules := &clientcmd.ClientConfigLoadingRules{ExplicitPath: path}
	overrides := &clientcmd.ConfigOverrides{CurrentContext: kubeContext}

	return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, overrides).ClientConfig()
}

func defaultLoadEKS(ctx context.Context, region string, clusterName string) (*rest.Config, error) {
	kubeconfig, err := runCommandForConfig(ctx, "aws", "eks", "update-kubeconfig", "--dry-run", "--name", clusterName, "--region", region)
	if err != nil {
		return nil, err
	}

	return clientcmd.RESTConfigFromKubeConfig(kubeconfig)
}

func defaultLoadGKE(ctx context.Context, project string, location string, clusterName string) (*rest.Config, error) {
	description, err := runCommandForConfig(
		ctx,
		"gcloud", "container", "clusters", "describe", clusterName,
		"--location", location,
		"--project", project,
		"--format=json",
	)
	if err != nil {
		return nil, err
	}

	var cluster struct {
		Endpoint   string `json:"endpoint"`
		MasterAuth struct {
			ClusterCACertificate string `json:"clusterCaCertificate"`
		} `json:"masterAuth"`
	}
	if err := json.Unmarshal(description, &cluster); err != nil {
		return nil, err
	}

	caData, err := base64.StdEncoding.DecodeString(cluster.MasterAuth.ClusterCACertificate)
	if err != nil {
		return nil, err
	}

	return &rest.Config{
		Host: "https://" + cluster.Endpoint,
		TLSClientConfig: rest.TLSClientConfig{
			CAData: caData,
		},
		ExecProvider: &clientcmdapi.ExecConfig{
			APIVersion:  "client.authentication.k8s.io/v1beta1",
			Command:     "gke-gcloud-auth-plugin",
			InstallHint: "install gke-gcloud-auth-plugin to authenticate to GKE clusters",
		},
	}, nil
}

func defaultLoadAKS(ctx context.Context, subscriptionID string, resourceGroup string, clusterName string) (*rest.Config, error) {
	kubeconfig, err := runCommandForConfig(
		ctx,
		"az", "aks", "get-credentials",
		"--subscription", subscriptionID,
		"--resource-group", resourceGroup,
		"--name", clusterName,
		"--file", "-",
		"--format", "exec",
	)
	if err != nil {
		return nil, err
	}

	return clientcmd.RESTConfigFromKubeConfig(kubeconfig)
}

func normalizeKubernetesAuthProvider(provider string) string {
	return strings.ToLower(strings.TrimSpace(provider))
}

func runCommandForConfig(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)

	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("%s %s: %s", name, strings.Join(args, " "), strings.TrimSpace(string(exitErr.Stderr)))
		}
		return nil, err
	}

	return output, nil
}
