package identity

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	awsec2 "github.com/aws/aws-sdk-go-v2/service/ec2"
	awsec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"k8s.io/client-go/kubernetes"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/moolen/aegis/internal/config"
)

type StartableResolver interface {
	Start(context.Context, time.Duration) error
	Resolve(net.IP) (*Identity, error)
}

type kubernetesRuntimeProviderDeps struct {
	loadRESTConfig         func(string) (*rest.Config, error)
	newKubernetesPodSource func(*rest.Config) (KubernetesPodSource, error)
	newKubernetesProvider  func(KubernetesProviderConfig, *slog.Logger) (StartableResolver, error)
}

type ec2RuntimeProviderDeps struct {
	loadAWSConfig  func(context.Context, string) (aws.Config, error)
	newEC2Source   func(aws.Config) (EC2InstanceSource, error)
	newEC2Provider func(EC2ProviderConfig, *slog.Logger) (StartableResolver, error)
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

var newKubernetesProvider = func(cfg KubernetesProviderConfig, logger *slog.Logger) (StartableResolver, error) {
	return NewKubernetesProvider(cfg, logger)
}

var loadAWSConfig = func(ctx context.Context, region string) (aws.Config, error) {
	return awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
}

var newEC2Source = func(cfg aws.Config) (EC2InstanceSource, error) {
	return ec2DescribeInstanceSource{client: awsec2.NewFromConfig(cfg)}, nil
}

var newEC2Provider = func(cfg EC2ProviderConfig, logger *slog.Logger) (StartableResolver, error) {
	return NewEC2Provider(cfg, logger)
}

func defaultKubernetesRuntimeProviderDeps() kubernetesRuntimeProviderDeps {
	return kubernetesRuntimeProviderDeps{
		loadRESTConfig:         loadRESTConfig,
		newKubernetesPodSource: newKubernetesPodSource,
		newKubernetesProvider:  newKubernetesProvider,
	}
}

func defaultEC2RuntimeProviderDeps() ec2RuntimeProviderDeps {
	return ec2RuntimeProviderDeps{
		loadAWSConfig:  loadAWSConfig,
		newEC2Source:   newEC2Source,
		newEC2Provider: newEC2Provider,
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

type ec2DescribeAPI interface {
	DescribeInstances(context.Context, *awsec2.DescribeInstancesInput, ...func(*awsec2.Options)) (*awsec2.DescribeInstancesOutput, error)
}

type ec2DescribeInstanceSource struct {
	client ec2DescribeAPI
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

func NewEC2RuntimeProvider(cfg config.EC2DiscoveryConfig, logger *slog.Logger) (RuntimeProvider, error) {
	pollInterval := 30 * time.Second
	if cfg.PollInterval != nil {
		pollInterval = *cfg.PollInterval
	}

	cfg.PollInterval = &pollInterval
	return newEC2RuntimeProvider(cfg, logger, defaultEC2RuntimeProviderDeps())
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

	provider, err := deps.newKubernetesProvider(KubernetesProviderConfig{
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

func newEC2RuntimeProvider(cfg config.EC2DiscoveryConfig, logger *slog.Logger, deps ec2RuntimeProviderDeps) (RuntimeProvider, error) {
	awsCfg, err := deps.loadAWSConfig(context.Background(), cfg.Region)
	if err != nil {
		return RuntimeProvider{}, fmt.Errorf("load aws config for %s: %w", cfg.Name, err)
	}

	source, err := deps.newEC2Source(awsCfg)
	if err != nil {
		return RuntimeProvider{}, fmt.Errorf("build ec2 source for %s: %w", cfg.Name, err)
	}

	var pollInterval time.Duration
	if cfg.PollInterval != nil {
		pollInterval = *cfg.PollInterval
	}

	provider, err := deps.newEC2Provider(EC2ProviderConfig{
		Name:         cfg.Name,
		Source:       source,
		TagFilters:   ec2TagFiltersFromConfig(cfg.TagFilters),
		PollInterval: pollInterval,
	}, logger)
	if err != nil {
		return RuntimeProvider{}, err
	}

	return RuntimeProvider{
		Name:     cfg.Name,
		Kind:     "ec2",
		Provider: provider,
	}, nil
}

func (s ec2DescribeInstanceSource) Instances(ctx context.Context, filters []EC2TagFilter) ([]EC2Instance, error) {
	input := &awsec2.DescribeInstancesInput{
		Filters: ec2Filters(filters),
	}

	paginator := awsec2.NewDescribeInstancesPaginator(s.client, input)

	var instances []EC2Instance
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, reservation := range page.Reservations {
			for _, instance := range reservation.Instances {
				if instance.PrivateIpAddress == nil || instance.InstanceId == nil {
					continue
				}

				instances = append(instances, EC2Instance{
					ID:        aws.ToString(instance.InstanceId),
					PrivateIP: aws.ToString(instance.PrivateIpAddress),
					Tags:      ec2Tags(instance.Tags),
				})
			}
		}
	}

	return instances, nil
}

func ec2TagFiltersFromConfig(filters []config.EC2TagFilterConfig) []EC2TagFilter {
	if len(filters) == 0 {
		return nil
	}

	out := make([]EC2TagFilter, len(filters))
	for i, filter := range filters {
		out[i] = EC2TagFilter{
			Key:    filter.Key,
			Values: append([]string(nil), filter.Values...),
		}
	}

	return out
}

func ec2Filters(filters []EC2TagFilter) []awsec2types.Filter {
	if len(filters) == 0 {
		return nil
	}

	out := make([]awsec2types.Filter, len(filters))
	for i, filter := range filters {
		out[i] = awsec2types.Filter{
			Name:   aws.String("tag:" + filter.Key),
			Values: append([]string(nil), filter.Values...),
		}
	}

	return out
}

func ec2Tags(tags []awsec2types.Tag) map[string]string {
	if len(tags) == 0 {
		return map[string]string{}
	}

	out := make(map[string]string, len(tags))
	for _, tag := range tags {
		if tag.Key == nil {
			continue
		}
		out[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
	}

	return out
}
