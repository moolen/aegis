package identity

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"golang.org/x/oauth2"
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

func TestBuildEKSRESTConfigUsesClusterMetadataAndBearerTokenSource(t *testing.T) {
	ctx := context.WithValue(context.Background(), struct{}{}, "ctx")
	clusterConn := managedClusterConnection{
		Host:   "https://eks.example",
		CAData: []byte("eks-ca"),
	}
	tokenSource := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "eks-token"})

	var gotDescribeCtx context.Context
	var gotTokenCtx context.Context
	cfg, err := buildEKSRESTConfig(ctx, "eu-central-1", "cluster-a", eksRESTConfigDeps{
		describeCluster: func(ctx context.Context, region string, clusterName string) (managedClusterConnection, error) {
			gotDescribeCtx = ctx
			if region != "eu-central-1" {
				t.Fatalf("describeCluster region = %q, want eu-central-1", region)
			}
			if clusterName != "cluster-a" {
				t.Fatalf("describeCluster clusterName = %q, want cluster-a", clusterName)
			}
			return clusterConn, nil
		},
		tokenSource: func(ctx context.Context, region string, clusterName string) (oauth2.TokenSource, error) {
			gotTokenCtx = ctx
			if region != "eu-central-1" {
				t.Fatalf("tokenSource region = %q, want eu-central-1", region)
			}
			if clusterName != "cluster-a" {
				t.Fatalf("tokenSource clusterName = %q, want cluster-a", clusterName)
			}
			return tokenSource, nil
		},
	})
	if err != nil {
		t.Fatalf("buildEKSRESTConfig() error = %v", err)
	}
	if gotDescribeCtx != ctx {
		t.Fatal("describeCluster context was not forwarded")
	}
	if gotTokenCtx != ctx {
		t.Fatal("tokenSource context was not forwarded")
	}
	if cfg.Host != clusterConn.Host {
		t.Fatalf("config host = %q, want %q", cfg.Host, clusterConn.Host)
	}
	if string(cfg.TLSClientConfig.CAData) != string(clusterConn.CAData) {
		t.Fatalf("config CAData = %q, want %q", cfg.TLSClientConfig.CAData, clusterConn.CAData)
	}
	if cfg.ExecProvider != nil {
		t.Fatalf("config ExecProvider = %#v, want nil", cfg.ExecProvider)
	}
	authHeader := authorizationHeader(t, cfg)
	if authHeader != "Bearer eks-token" {
		t.Fatalf("authorization header = %q, want Bearer eks-token", authHeader)
	}
}

func TestBuildGKERestConfigUsesClusterMetadataAndBearerTokenSource(t *testing.T) {
	requestCtx := context.WithValue(context.Background(), struct{}{}, "ctx")
	clusterConn := managedClusterConnection{
		Host:   "https://gke.example",
		CAData: []byte("gke-ca"),
	}
	tokenSource := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "gke-token"})

	cfg, err := buildGKERestConfig(requestCtx, "prod-project", "europe-west1", "cluster-b", gkeRESTConfigDeps{
		describeCluster: func(ctx context.Context, project string, location string, clusterName string) (managedClusterConnection, error) {
			if ctx != requestCtx {
				t.Fatal("describeCluster context mismatch")
			}
			if project != "prod-project" || location != "europe-west1" || clusterName != "cluster-b" {
				t.Fatalf("describeCluster args = %q/%q/%q", project, location, clusterName)
			}
			return clusterConn, nil
		},
		tokenSource: func(ctx context.Context) (oauth2.TokenSource, error) {
			if ctx != requestCtx {
				t.Fatal("tokenSource context mismatch")
			}
			return tokenSource, nil
		},
	})
	if err != nil {
		t.Fatalf("buildGKERestConfig() error = %v", err)
	}
	if cfg.Host != clusterConn.Host {
		t.Fatalf("config host = %q, want %q", cfg.Host, clusterConn.Host)
	}
	if string(cfg.TLSClientConfig.CAData) != string(clusterConn.CAData) {
		t.Fatalf("config CAData = %q, want %q", cfg.TLSClientConfig.CAData, clusterConn.CAData)
	}
	if cfg.ExecProvider != nil {
		t.Fatalf("config ExecProvider = %#v, want nil", cfg.ExecProvider)
	}
	authHeader := authorizationHeader(t, cfg)
	if authHeader != "Bearer gke-token" {
		t.Fatalf("authorization header = %q, want Bearer gke-token", authHeader)
	}
}

func TestBuildAKSRESTConfigUsesReturnedKubeconfigAndAmbientTokenSource(t *testing.T) {
	requestCtx := context.WithValue(context.Background(), struct{}{}, "ctx")
	kubeconfig := []byte(`
apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: YWtzLWNh
    server: https://aks.example
  name: cluster
contexts:
- context:
    cluster: cluster
    user: user
  name: context
current-context: context
kind: Config
users:
- name: user
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1beta1
      command: kubelogin
      args:
      - get-token
      - --server-id
      - server-app-id
`)
	tokenSource := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "aks-token"})

	cfg, err := buildAKSRESTConfig(requestCtx, "sub-123", "rg-platform", "cluster-c", aksRESTConfigDeps{
		loadKubeconfig: func(ctx context.Context, subscriptionID string, resourceGroup string, clusterName string) ([]byte, error) {
			if ctx != requestCtx {
				t.Fatal("loadKubeconfig context mismatch")
			}
			if subscriptionID != "sub-123" || resourceGroup != "rg-platform" || clusterName != "cluster-c" {
				t.Fatalf("loadKubeconfig args = %q/%q/%q", subscriptionID, resourceGroup, clusterName)
			}
			return kubeconfig, nil
		},
		tokenSource: func(ctx context.Context, rawKubeconfig []byte) (oauth2.TokenSource, error) {
			if ctx != requestCtx {
				t.Fatal("tokenSource context mismatch")
			}
			if string(rawKubeconfig) != string(kubeconfig) {
				t.Fatal("tokenSource received unexpected kubeconfig")
			}
			return tokenSource, nil
		},
	})
	if err != nil {
		t.Fatalf("buildAKSRESTConfig() error = %v", err)
	}
	if cfg.Host != "https://aks.example" {
		t.Fatalf("config host = %q, want https://aks.example", cfg.Host)
	}
	if string(cfg.TLSClientConfig.CAData) != "aks-ca" {
		t.Fatalf("config CAData = %q, want aks-ca", cfg.TLSClientConfig.CAData)
	}
	if cfg.ExecProvider != nil {
		t.Fatalf("config ExecProvider = %#v, want nil", cfg.ExecProvider)
	}
	if cfg.AuthProvider != nil {
		t.Fatalf("config AuthProvider = %#v, want nil", cfg.AuthProvider)
	}
	authHeader := authorizationHeader(t, cfg)
	if authHeader != "Bearer aks-token" {
		t.Fatalf("authorization header = %q, want Bearer aks-token", authHeader)
	}
}

func TestBuildAKSRESTConfigKeepsNonExecKubeconfigAuth(t *testing.T) {
	kubeconfig := []byte(`
apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: YWtzLWNh
    server: https://aks.example
  name: cluster
contexts:
- context:
    cluster: cluster
    user: user
  name: context
current-context: context
kind: Config
users:
- name: user
  user:
    token: direct-token
`)

	cfg, err := buildAKSRESTConfig(context.Background(), "sub-123", "rg-platform", "cluster-c", aksRESTConfigDeps{
		loadKubeconfig: func(context.Context, string, string, string) ([]byte, error) {
			return kubeconfig, nil
		},
		tokenSource: func(context.Context, []byte) (oauth2.TokenSource, error) {
			t.Fatal("tokenSource should not be called for non-exec kubeconfig")
			return nil, nil
		},
	})
	if err != nil {
		t.Fatalf("buildAKSRESTConfig() error = %v", err)
	}
	if cfg.Host != "https://aks.example" {
		t.Fatalf("config host = %q, want https://aks.example", cfg.Host)
	}
	if cfg.BearerToken != "direct-token" {
		t.Fatalf("config bearer token = %q, want direct-token", cfg.BearerToken)
	}
}

func TestBuildAKSRESTConfigRejectsMalformedExecKubeconfig(t *testing.T) {
	kubeconfig := []byte(`
apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: YWtzLWNh
    server: https://aks.example
  name: cluster
contexts:
- context:
    cluster: cluster
    user: user
  name: context
current-context: context
kind: Config
users:
- name: user
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1beta1
      command: kubelogin
`)

	_, err := buildAKSRESTConfig(context.Background(), "sub-123", "rg-platform", "cluster-c", aksRESTConfigDeps{
		loadKubeconfig: func(context.Context, string, string, string) ([]byte, error) {
			return kubeconfig, nil
		},
		tokenSource: func(context.Context, []byte) (oauth2.TokenSource, error) {
			t.Fatal("tokenSource should not be called when exec kubeconfig is malformed")
			return nil, nil
		},
	})
	if err == nil {
		t.Fatal("expected malformed exec kubeconfig error")
	}
	if !strings.Contains(err.Error(), "--server-id") {
		t.Fatalf("error = %q, want missing server-id message", err)
	}
}

func TestBuildAKSRESTConfigPropagatesKubeconfigErrors(t *testing.T) {
	loadErr := errors.New("aks unavailable")

	_, err := buildAKSRESTConfig(context.Background(), "sub-123", "rg-platform", "cluster-c", aksRESTConfigDeps{
		loadKubeconfig: func(context.Context, string, string, string) ([]byte, error) {
			return nil, loadErr
		},
	})
	if !errors.Is(err, loadErr) {
		t.Fatalf("error = %v, want wrapped kubeconfig error", err)
	}
}

func TestApplyBearerTokenSourcePreservesExistingWrapTransport(t *testing.T) {
	cfg := applyBearerTokenSource(&rest.Config{
		WrapTransport: func(rt http.RoundTripper) http.RoundTripper {
			return roundTripFunc(func(req *http.Request) (*http.Response, error) {
				req.Header.Set("X-Existing-Wrap", "present")
				return rt.RoundTrip(req)
			})
		},
	}, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "wrapped-token"}))

	headers := requestHeaders(t, cfg)
	if headers.Get("Authorization") != "Bearer wrapped-token" {
		t.Fatalf("authorization header = %q, want Bearer wrapped-token", headers.Get("Authorization"))
	}
	if headers.Get("X-Existing-Wrap") != "present" {
		t.Fatalf("X-Existing-Wrap header = %q, want present", headers.Get("X-Existing-Wrap"))
	}
}

func TestApplyBearerTokenSourceRefreshesTokenAcrossRequests(t *testing.T) {
	tokenSource := &sequenceTokenSource{
		tokens: []oauth2.Token{
			{AccessToken: "token-a"},
			{AccessToken: "token-b"},
		},
	}
	cfg := applyBearerTokenSource(&rest.Config{}, tokenSource)

	first := requestHeaders(t, cfg)
	second := requestHeaders(t, cfg)

	if first.Get("Authorization") != "Bearer token-a" {
		t.Fatalf("first authorization header = %q, want Bearer token-a", first.Get("Authorization"))
	}
	if second.Get("Authorization") != "Bearer token-b" {
		t.Fatalf("second authorization header = %q, want Bearer token-b", second.Get("Authorization"))
	}
	if tokenSource.calls != 2 {
		t.Fatalf("token source calls = %d, want 2", tokenSource.calls)
	}
}

func TestAKSTokenRequestParametersSelectsCurrentContextServerID(t *testing.T) {
	serverID, tenantID, err := aksTokenRequestParameters([]byte(`
apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: YQ==
    server: https://aks.example
  name: cluster-a
- cluster:
    certificate-authority-data: Yg==
    server: https://aks-b.example
  name: cluster-b
contexts:
- context:
    cluster: cluster-a
    user: user-a
  name: ctx-a
- context:
    cluster: cluster-b
    user: user-b
  name: ctx-b
current-context: ctx-b
kind: Config
users:
- name: user-a
  user:
    exec:
      command: kubelogin
      args:
      - get-token
      - --server-id
      - ignored
- name: user-b
  user:
    exec:
      command: kubelogin
      args:
      - get-token
      - --server-id=server-b
      - --tenant-id
      - tenant-b
`))
	if err != nil {
		t.Fatalf("aksTokenRequestParameters() error = %v", err)
	}
	if serverID != "server-b" {
		t.Fatalf("serverID = %q, want server-b", serverID)
	}
	if tenantID != "tenant-b" {
		t.Fatalf("tenantID = %q, want tenant-b", tenantID)
	}
}

func TestAKSTokenRequestParametersFallsBackToFirstContext(t *testing.T) {
	serverID, tenantID, err := aksTokenRequestParameters([]byte(`
apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: YQ==
    server: https://aks.example
  name: cluster-a
contexts:
- context:
    cluster: cluster-a
    user: user-a
  name: ctx-a
kind: Config
users:
- name: user-a
  user:
    exec:
      command: kubelogin
      args:
      - get-token
      - --server-id
      - first-server
`))
	if err != nil {
		t.Fatalf("aksTokenRequestParameters() error = %v", err)
	}
	if serverID != "first-server" {
		t.Fatalf("serverID = %q, want first-server", serverID)
	}
	if tenantID != "" {
		t.Fatalf("tenantID = %q, want empty", tenantID)
	}
}

func TestAKSTokenRequestParametersRejectsMissingServerID(t *testing.T) {
	_, _, err := aksTokenRequestParameters([]byte(`
apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: YQ==
    server: https://aks.example
  name: cluster-a
contexts:
- context:
    cluster: cluster-a
    user: user-a
  name: ctx-a
current-context: ctx-a
kind: Config
users:
- name: user-a
  user:
    exec:
      command: kubelogin
      args:
      - get-token
`))
	if err == nil {
		t.Fatal("expected missing server-id error")
	}
	if !strings.Contains(err.Error(), "--server-id") {
		t.Fatalf("error = %q, want missing server-id message", err)
	}
}

func TestAzureOAuth2TokenSourceUsesConfiguredCredential(t *testing.T) {
	credential := &fakeAzureTokenCredential{
		token: azcore.AccessToken{
			Token:     "azure-token",
			ExpiresOn: time.Unix(123, 0).UTC(),
		},
	}
	source := azureOAuth2TokenSource{
		ctx:        context.Background(),
		credential: credential,
		options: policy.TokenRequestOptions{
			Scopes:   []string{"scope/.default"},
			TenantID: "tenant-a",
		},
	}

	token, err := source.Token()
	if err != nil {
		t.Fatalf("Token() error = %v", err)
	}
	if token.AccessToken != "azure-token" {
		t.Fatalf("access token = %q, want azure-token", token.AccessToken)
	}
	if !token.Expiry.Equal(time.Unix(123, 0).UTC()) {
		t.Fatalf("expiry = %s, want %s", token.Expiry, time.Unix(123, 0).UTC())
	}
	if credential.calls != 1 {
		t.Fatalf("credential calls = %d, want 1", credential.calls)
	}
	if len(credential.lastOptions.Scopes) != 1 || credential.lastOptions.Scopes[0] != "scope/.default" {
		t.Fatalf("credential scopes = %#v, want scope/.default", credential.lastOptions.Scopes)
	}
	if credential.lastOptions.TenantID != "tenant-a" {
		t.Fatalf("credential tenant = %q, want tenant-a", credential.lastOptions.TenantID)
	}
}

func TestNewAKSAmbientAzureCredentialUsesOnlyNonCLISources(t *testing.T) {
	envCred := &fakeAzureTokenCredential{}
	workloadCred := &fakeAzureTokenCredential{}
	managedCred := &fakeAzureTokenCredential{}

	var gotSources []azcore.TokenCredential
	credential, err := newAKSAmbientAzureCredential(aksAzureCredentialDeps{
		newEnvironmentCredential: func() (azcore.TokenCredential, error) {
			return envCred, nil
		},
		newWorkloadIdentityCredential: func() (azcore.TokenCredential, error) {
			return workloadCred, nil
		},
		newManagedIdentityCredential: func() (azcore.TokenCredential, error) {
			return managedCred, nil
		},
		newChainedTokenCredential: func(sources []azcore.TokenCredential) (azcore.TokenCredential, error) {
			gotSources = append([]azcore.TokenCredential(nil), sources...)
			return managedCred, nil
		},
	})
	if err != nil {
		t.Fatalf("newAKSAmbientAzureCredential() error = %v", err)
	}
	if credential != managedCred {
		t.Fatalf("credential = %v, want chained credential result", credential)
	}
	if len(gotSources) != 3 {
		t.Fatalf("chained sources len = %d, want 3", len(gotSources))
	}
	if gotSources[0] != envCred || gotSources[1] != workloadCred || gotSources[2] != managedCred {
		t.Fatalf("chained sources = %#v, want env/workload/managed order", gotSources)
	}
}

func authorizationHeader(t *testing.T, cfg *rest.Config) string {
	t.Helper()

	return requestHeaders(t, cfg).Get("Authorization")
}

func requestHeaders(t *testing.T, cfg *rest.Config) http.Header {
	t.Helper()

	transport := cfg.WrapTransport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("ok")),
			Request:    req,
		}, nil
	}))

	req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	if err != nil {
		t.Fatalf("http.NewRequest() error = %v", err)
	}

	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip() error = %v", err)
	}
	defer resp.Body.Close()

	return resp.Request.Header.Clone()
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

type sequenceTokenSource struct {
	tokens []oauth2.Token
	calls  int
}

func (s *sequenceTokenSource) Token() (*oauth2.Token, error) {
	if s.calls >= len(s.tokens) {
		return nil, errors.New("no more tokens")
	}
	token := s.tokens[s.calls]
	s.calls++
	return &token, nil
}

type fakeAzureTokenCredential struct {
	token       azcore.AccessToken
	calls       int
	lastOptions policy.TokenRequestOptions
}

func (c *fakeAzureTokenCredential) GetToken(_ context.Context, options policy.TokenRequestOptions) (azcore.AccessToken, error) {
	c.calls++
	c.lastOptions = options
	return c.token, nil
}
