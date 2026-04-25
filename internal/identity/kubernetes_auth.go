package identity

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"cloud.google.com/go/container/apiv1"
	"cloud.google.com/go/container/apiv1/containerpb"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice/v6"
	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	awseks "github.com/aws/aws-sdk-go-v2/service/eks"
	awseksTypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
	awssts "github.com/aws/aws-sdk-go-v2/service/sts"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

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

type managedClusterConnection struct {
	Host   string
	CAData []byte
}

type eksRESTConfigDeps struct {
	describeCluster func(ctx context.Context, region string, clusterName string) (managedClusterConnection, error)
	tokenSource     func(ctx context.Context, region string, clusterName string) (oauth2.TokenSource, error)
}

type gkeRESTConfigDeps struct {
	describeCluster func(ctx context.Context, project string, location string, clusterName string) (managedClusterConnection, error)
	tokenSource     func(ctx context.Context) (oauth2.TokenSource, error)
}

type aksRESTConfigDeps struct {
	loadKubeconfig func(ctx context.Context, subscriptionID string, resourceGroup string, clusterName string) ([]byte, error)
	tokenSource    func(ctx context.Context, rawKubeconfig []byte) (oauth2.TokenSource, error)
}

type aksAzureCredentialDeps struct {
	newEnvironmentCredential      func() (azcore.TokenCredential, error)
	newWorkloadIdentityCredential func() (azcore.TokenCredential, error)
	newManagedIdentityCredential  func() (azcore.TokenCredential, error)
	newChainedTokenCredential     func([]azcore.TokenCredential) (azcore.TokenCredential, error)
}

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
	return buildEKSRESTConfig(ctx, region, clusterName, eksRESTConfigDeps{
		describeCluster: defaultDescribeEKSCluster,
		tokenSource:     defaultEKSTokenSource,
	})
}

func defaultLoadGKE(ctx context.Context, project string, location string, clusterName string) (*rest.Config, error) {
	return buildGKERestConfig(ctx, project, location, clusterName, gkeRESTConfigDeps{
		describeCluster: defaultDescribeGKECluster,
		tokenSource:     defaultGKETokenSource,
	})
}

func defaultLoadAKS(ctx context.Context, subscriptionID string, resourceGroup string, clusterName string) (*rest.Config, error) {
	return buildAKSRESTConfig(ctx, subscriptionID, resourceGroup, clusterName, aksRESTConfigDeps{
		loadKubeconfig: defaultLoadAKSKubeconfig,
		tokenSource:    defaultAKSTokenSource,
	})
}

func normalizeKubernetesAuthProvider(provider string) string {
	return strings.ToLower(strings.TrimSpace(provider))
}

func buildEKSRESTConfig(ctx context.Context, region string, clusterName string, deps eksRESTConfigDeps) (*rest.Config, error) {
	clusterConn, err := deps.describeCluster(ctx, region, clusterName)
	if err != nil {
		return nil, err
	}

	tokenSource, err := deps.tokenSource(ctx, region, clusterName)
	if err != nil {
		return nil, err
	}

	return newBearerTokenRESTConfig(clusterConn, tokenSource), nil
}

func buildGKERestConfig(ctx context.Context, project string, location string, clusterName string, deps gkeRESTConfigDeps) (*rest.Config, error) {
	clusterConn, err := deps.describeCluster(ctx, project, location, clusterName)
	if err != nil {
		return nil, err
	}

	tokenSource, err := deps.tokenSource(ctx)
	if err != nil {
		return nil, err
	}

	return newBearerTokenRESTConfig(clusterConn, tokenSource), nil
}

func buildAKSRESTConfig(ctx context.Context, subscriptionID string, resourceGroup string, clusterName string, deps aksRESTConfigDeps) (*rest.Config, error) {
	rawKubeconfig, err := deps.loadKubeconfig(ctx, subscriptionID, resourceGroup, clusterName)
	if err != nil {
		return nil, err
	}

	restCfg, err := clientcmd.RESTConfigFromKubeConfig(rawKubeconfig)
	if err != nil {
		return nil, err
	}

	_, _, requiresAmbientToken, err := aksExecAuthTokenRequestParameters(rawKubeconfig)
	if err != nil {
		return nil, err
	}
	if !requiresAmbientToken {
		return restCfg, nil
	}

	tokenSource, err := deps.tokenSource(ctx, rawKubeconfig)
	if err != nil {
		return nil, err
	}

	return applyBearerTokenSource(restCfg, tokenSource), nil
}

func defaultDescribeEKSCluster(ctx context.Context, region string, clusterName string) (managedClusterConnection, error) {
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return managedClusterConnection{}, err
	}

	client := awseks.NewFromConfig(awsCfg)
	output, err := client.DescribeCluster(ctx, &awseks.DescribeClusterInput{Name: aws.String(clusterName)})
	if err != nil {
		return managedClusterConnection{}, err
	}

	return managedClusterConnectionFromEKS(output.Cluster)
}

func defaultEKSTokenSource(ctx context.Context, region string, clusterName string) (oauth2.TokenSource, error) {
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, err
	}

	return oauth2.ReuseTokenSource(nil, &eksTokenSource{
		credentials:      awsCfg.Credentials,
		signer:           v4.NewSigner(),
		endpointResolver: awssts.NewDefaultEndpointResolverV2(),
		region:           region,
		clusterName:      clusterName,
	}), nil
}

func defaultDescribeGKECluster(ctx context.Context, project string, location string, clusterName string) (managedClusterConnection, error) {
	client, err := container.NewClusterManagerClient(ctx)
	if err != nil {
		return managedClusterConnection{}, err
	}
	defer client.Close()

	cluster, err := client.GetCluster(ctx, &containerpb.GetClusterRequest{
		Name: gkeClusterResourceName(project, location, clusterName),
	})
	if err != nil {
		return managedClusterConnection{}, err
	}

	return managedClusterConnectionFromGKE(cluster)
}

func defaultGKETokenSource(ctx context.Context) (oauth2.TokenSource, error) {
	return google.DefaultTokenSource(ctx, container.DefaultAuthScopes()...)
}

func defaultLoadAKSKubeconfig(ctx context.Context, subscriptionID string, resourceGroup string, clusterName string) ([]byte, error) {
	credential, err := newAKSAmbientAzureCredential(defaultAKSAzureCredentialDeps())
	if err != nil {
		return nil, err
	}

	client, err := armcontainerservice.NewManagedClustersClient(subscriptionID, credential, nil)
	if err != nil {
		return nil, err
	}

	format := armcontainerservice.FormatExec
	response, err := client.ListClusterUserCredentials(ctx, resourceGroup, clusterName, &armcontainerservice.ManagedClustersClientListClusterUserCredentialsOptions{
		Format: &format,
	})
	if err != nil {
		return nil, err
	}

	if len(response.Kubeconfigs) == 0 || len(response.Kubeconfigs[0].Value) == 0 {
		return nil, fmt.Errorf("aks cluster %s returned no kubeconfig", clusterName)
	}

	return append([]byte(nil), response.Kubeconfigs[0].Value...), nil
}

func defaultAKSTokenSource(ctx context.Context, rawKubeconfig []byte) (oauth2.TokenSource, error) {
	serverID, tenantID, err := aksTokenRequestParameters(rawKubeconfig)
	if err != nil {
		return nil, err
	}

	credential, err := newAKSAmbientAzureCredential(defaultAKSAzureCredentialDeps())
	if err != nil {
		return nil, err
	}

	return oauth2.ReuseTokenSource(nil, &azureOAuth2TokenSource{
		ctx:        ctx,
		credential: credential,
		options: policy.TokenRequestOptions{
			Scopes:   []string{serverID + "/.default"},
			TenantID: tenantID,
		},
	}), nil
}

func defaultAKSAzureCredentialDeps() aksAzureCredentialDeps {
	return aksAzureCredentialDeps{
		newEnvironmentCredential: func() (azcore.TokenCredential, error) {
			return azidentity.NewEnvironmentCredential(nil)
		},
		newWorkloadIdentityCredential: func() (azcore.TokenCredential, error) {
			return azidentity.NewWorkloadIdentityCredential(nil)
		},
		newManagedIdentityCredential: func() (azcore.TokenCredential, error) {
			return azidentity.NewManagedIdentityCredential(nil)
		},
		newChainedTokenCredential: func(sources []azcore.TokenCredential) (azcore.TokenCredential, error) {
			return azidentity.NewChainedTokenCredential(sources, &azidentity.ChainedTokenCredentialOptions{
				RetrySources: true,
			})
		},
	}
}

func newAKSAmbientAzureCredential(deps aksAzureCredentialDeps) (azcore.TokenCredential, error) {
	var sources []azcore.TokenCredential
	var lastErr error

	for _, constructor := range []func() (azcore.TokenCredential, error){
		deps.newEnvironmentCredential,
		deps.newWorkloadIdentityCredential,
		deps.newManagedIdentityCredential,
	} {
		if constructor == nil {
			continue
		}

		credential, err := constructor()
		if err != nil {
			lastErr = err
			continue
		}
		if credential != nil {
			sources = append(sources, credential)
		}
	}

	if len(sources) == 0 {
		if lastErr != nil {
			return nil, lastErr
		}
		return nil, fmt.Errorf("no ambient azure credential sources available for aks")
	}

	if deps.newChainedTokenCredential == nil {
		return nil, fmt.Errorf("aks chained azure credential constructor is not configured")
	}

	return deps.newChainedTokenCredential(sources)
}

func managedClusterConnectionFromEKS(cluster *awseksTypes.Cluster) (managedClusterConnection, error) {
	if cluster == nil {
		return managedClusterConnection{}, fmt.Errorf("eks cluster response was empty")
	}
	if cluster.CertificateAuthority == nil || strings.TrimSpace(aws.ToString(cluster.CertificateAuthority.Data)) == "" {
		return managedClusterConnection{}, fmt.Errorf("eks cluster %q did not include certificate authority data", aws.ToString(cluster.Name))
	}
	if strings.TrimSpace(aws.ToString(cluster.Endpoint)) == "" {
		return managedClusterConnection{}, fmt.Errorf("eks cluster %q did not include an endpoint", aws.ToString(cluster.Name))
	}

	caData, err := base64.StdEncoding.DecodeString(aws.ToString(cluster.CertificateAuthority.Data))
	if err != nil {
		return managedClusterConnection{}, err
	}

	return managedClusterConnection{
		Host:   normalizeKubernetesHost(aws.ToString(cluster.Endpoint)),
		CAData: caData,
	}, nil
}

func managedClusterConnectionFromGKE(cluster *containerpb.Cluster) (managedClusterConnection, error) {
	if cluster == nil {
		return managedClusterConnection{}, fmt.Errorf("gke cluster response was empty")
	}
	if strings.TrimSpace(cluster.GetEndpoint()) == "" {
		return managedClusterConnection{}, fmt.Errorf("gke cluster %q did not include an endpoint", cluster.GetName())
	}
	if cluster.GetMasterAuth() == nil || strings.TrimSpace(cluster.GetMasterAuth().GetClusterCaCertificate()) == "" {
		return managedClusterConnection{}, fmt.Errorf("gke cluster %q did not include certificate authority data", cluster.GetName())
	}

	caData, err := base64.StdEncoding.DecodeString(cluster.GetMasterAuth().GetClusterCaCertificate())
	if err != nil {
		return managedClusterConnection{}, err
	}

	return managedClusterConnection{
		Host:   normalizeKubernetesHost(cluster.GetEndpoint()),
		CAData: caData,
	}, nil
}

func newBearerTokenRESTConfig(clusterConn managedClusterConnection, tokenSource oauth2.TokenSource) *rest.Config {
	return applyBearerTokenSource(&rest.Config{
		Host: clusterConn.Host,
		TLSClientConfig: rest.TLSClientConfig{
			CAData: append([]byte(nil), clusterConn.CAData...),
		},
	}, tokenSource)
}

func applyBearerTokenSource(restCfg *rest.Config, tokenSource oauth2.TokenSource) *rest.Config {
	cfg := rest.CopyConfig(restCfg)
	previousWrap := cfg.WrapTransport
	cfg.ExecProvider = nil
	cfg.AuthProvider = nil
	cfg.BearerToken = ""
	cfg.BearerTokenFile = ""
	cfg.WrapTransport = func(rt http.RoundTripper) http.RoundTripper {
		if previousWrap != nil {
			rt = previousWrap(rt)
		}
		return bearerTokenRoundTripper{
			base:        rt,
			tokenSource: tokenSource,
		}
	}

	return cfg
}

func gkeClusterResourceName(project string, location string, clusterName string) string {
	return fmt.Sprintf("projects/%s/locations/%s/clusters/%s", project, location, clusterName)
}

func aksTokenRequestParameters(rawKubeconfig []byte) (string, string, error) {
	serverID, tenantID, ok, err := aksExecAuthTokenRequestParameters(rawKubeconfig)
	if err != nil {
		return "", "", err
	}
	if !ok {
		return "", "", fmt.Errorf("aks kubeconfig did not include exec auth configuration")
	}

	return serverID, tenantID, nil
}

func aksExecAuthTokenRequestParameters(rawKubeconfig []byte) (string, string, bool, error) {
	cfg, err := clientcmd.Load(rawKubeconfig)
	if err != nil {
		return "", "", false, err
	}

	contextName := cfg.CurrentContext
	if strings.TrimSpace(contextName) == "" {
		for name := range cfg.Contexts {
			contextName = name
			break
		}
	}

	contextCfg, ok := cfg.Contexts[contextName]
	if !ok || contextCfg == nil {
		return "", "", false, fmt.Errorf("aks kubeconfig did not include a usable current context")
	}

	authInfo, ok := cfg.AuthInfos[contextCfg.AuthInfo]
	if !ok || authInfo == nil {
		return "", "", false, fmt.Errorf("aks kubeconfig did not include auth info for context %q", contextName)
	}
	if authInfo.Exec == nil {
		return "", "", false, nil
	}
	if !isAKSKubeloginExec(authInfo.Exec.Command) {
		return "", "", false, nil
	}

	serverID := execArgValue(authInfo.Exec.Args, "--server-id")
	if strings.TrimSpace(serverID) == "" {
		return "", "", false, fmt.Errorf("aks kubeconfig did not include --server-id in exec args")
	}

	return serverID, execArgValue(authInfo.Exec.Args, "--tenant-id"), true, nil
}

func execArgValue(args []string, flag string) string {
	for i := 0; i < len(args); i++ {
		if args[i] == flag && i+1 < len(args) {
			return args[i+1]
		}
		if strings.HasPrefix(args[i], flag+"=") {
			return strings.TrimPrefix(args[i], flag+"=")
		}
	}

	return ""
}

func isAKSKubeloginExec(command string) bool {
	base := strings.ToLower(filepath.Base(strings.TrimSpace(command)))
	return base == "kubelogin" || base == "kubelogin.exe"
}

func normalizeKubernetesHost(host string) string {
	trimmed := strings.TrimSpace(host)
	if strings.HasPrefix(trimmed, "https://") || strings.HasPrefix(trimmed, "http://") {
		return trimmed
	}
	return "https://" + trimmed
}

type bearerTokenRoundTripper struct {
	base        http.RoundTripper
	tokenSource oauth2.TokenSource
}

func (rt bearerTokenRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	token, err := rt.tokenSource.Token()
	if err != nil {
		return nil, err
	}

	cloned := req.Clone(req.Context())
	cloned.Header.Set("Authorization", "Bearer "+token.AccessToken)
	base := rt.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(cloned)
}

type azureOAuth2TokenSource struct {
	ctx        context.Context
	credential azcore.TokenCredential
	options    policy.TokenRequestOptions
}

func (s *azureOAuth2TokenSource) Token() (*oauth2.Token, error) {
	token, err := s.credential.GetToken(s.ctx, s.options)
	if err != nil {
		return nil, err
	}

	return &oauth2.Token{
		AccessToken: token.Token,
		Expiry:      token.ExpiresOn,
	}, nil
}

type eksTokenSource struct {
	credentials      aws.CredentialsProvider
	signer           *v4.Signer
	endpointResolver awssts.EndpointResolverV2
	region           string
	clusterName      string
}

func (s *eksTokenSource) Token() (*oauth2.Token, error) {
	credentials, err := s.credentials.Retrieve(context.Background())
	if err != nil {
		return nil, err
	}

	endpoint, err := s.endpointResolver.ResolveEndpoint(context.Background(), awssts.EndpointParameters{
		Region:            aws.String(s.region),
		UseGlobalEndpoint: aws.Bool(false),
	})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodGet, endpoint.URI.String(), nil)
	if err != nil {
		return nil, err
	}

	query := req.URL.Query()
	query.Set("Action", "GetCallerIdentity")
	query.Set("Version", "2011-06-15")
	query.Set("X-Amz-Expires", "60")
	req.URL.RawQuery = query.Encode()
	req.Header.Set("x-k8s-aws-id", s.clusterName)

	signedURL, _, err := s.signer.PresignHTTP(
		context.Background(),
		credentials,
		req,
		emptyPayloadSHA256,
		awssts.ServiceID,
		s.region,
		time.Now().UTC(),
	)
	if err != nil {
		return nil, err
	}

	return &oauth2.Token{
		AccessToken: "k8s-aws-v1." + base64.RawURLEncoding.EncodeToString([]byte(signedURL)),
		Expiry:      time.Now().Add(14 * time.Minute),
	}, nil
}

const emptyPayloadSHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
