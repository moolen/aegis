package identity

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
)

type KubernetesPodNamespaceClient interface {
	List(ctx context.Context, options metav1.ListOptions) (*corev1.PodList, error)
	Watch(ctx context.Context, options metav1.ListOptions) (watch.Interface, error)
}

type KubernetesPodSource interface {
	Pods(namespace string) KubernetesPodNamespaceClient
}

type KubernetesProviderConfig struct {
	Name         string
	Source       KubernetesPodSource
	Namespaces   []string
	ResyncPeriod time.Duration
}

type KubernetesProvider struct {
	name      string
	informers []cache.SharedIndexInformer
	logger    *slog.Logger

	mu      sync.RWMutex
	byIP    map[string]*Identity
	ipByPod map[string]string
	started bool
}

func NewKubernetesProvider(cfg KubernetesProviderConfig, logger *slog.Logger) (*KubernetesProvider, error) {
	if cfg.Name == "" {
		return nil, fmt.Errorf("kubernetes provider name is required")
	}
	if cfg.Source == nil {
		return nil, fmt.Errorf("kubernetes provider source is required")
	}
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(ioDiscard{}, nil))
	}

	provider := &KubernetesProvider{
		name:    cfg.Name,
		logger:  logger.With("provider", cfg.Name, "source", "kubernetes"),
		byIP:    make(map[string]*Identity),
		ipByPod: make(map[string]string),
	}

	resyncPeriod := cfg.ResyncPeriod
	if resyncPeriod <= 0 {
		resyncPeriod = time.Minute
	}

	namespaces := cfg.Namespaces
	if len(namespaces) == 0 {
		namespaces = []string{metav1.NamespaceAll}
	}

	for _, namespace := range namespaces {
		source := cfg.Source.Pods(namespace)
		listWatch := &cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				return source.List(context.Background(), options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				return source.Watch(context.Background(), options)
			},
		}
		informer := cache.NewSharedIndexInformer(
			cache.ToListWatcherWithWatchListSemantics(listWatch, watchListSemanticsUnsupported{}),
			&corev1.Pod{},
			resyncPeriod,
			cache.Indexers{},
		)
		_, err := informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
			AddFunc:    provider.onAdd,
			UpdateFunc: provider.onUpdate,
			DeleteFunc: provider.onDelete,
		})
		if err != nil {
			return nil, fmt.Errorf("register pod event handler for namespace %q: %w", namespace, err)
		}
		provider.informers = append(provider.informers, informer)
	}

	return provider, nil
}

func (p *KubernetesProvider) Start(ctx context.Context) error {
	p.mu.Lock()
	if p.started {
		p.mu.Unlock()
		return nil
	}
	p.started = true
	p.mu.Unlock()

	for _, informer := range p.informers {
		go informer.Run(ctx.Done())
	}

	hasSynced := make([]cache.InformerSynced, 0, len(p.informers))
	for _, informer := range p.informers {
		hasSynced = append(hasSynced, informer.HasSynced)
	}

	if ok := cache.WaitForCacheSync(ctx.Done(), hasSynced...); !ok {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("sync kubernetes provider caches: %w", err)
		}
		return fmt.Errorf("sync kubernetes provider caches")
	}

	return nil
}

func (p *KubernetesProvider) Resolve(ip net.IP) (*Identity, error) {
	if ip == nil {
		return nil, nil
	}

	p.mu.RLock()
	defer p.mu.RUnlock()

	id := p.byIP[ip.String()]
	if id == nil {
		return nil, nil
	}

	return cloneIdentity(id), nil
}

func (p *KubernetesProvider) onAdd(obj interface{}) {
	pod := podFromObject(obj)
	if pod == nil {
		return
	}
	p.upsertPod(pod, "")
}

func (p *KubernetesProvider) onUpdate(oldObj, newObj interface{}) {
	newPod := podFromObject(newObj)
	if newPod == nil {
		return
	}

	oldPod := podFromObject(oldObj)
	oldIP := ""
	if oldPod != nil {
		oldIP = oldPod.Status.PodIP
	}

	p.upsertPod(newPod, oldIP)
}

func (p *KubernetesProvider) onDelete(obj interface{}) {
	pod := podFromObject(obj)
	if pod == nil {
		return
	}

	key := podKey(pod)

	p.mu.Lock()
	defer p.mu.Unlock()

	ip := p.ipByPod[key]
	if ip == "" {
		ip = pod.Status.PodIP
	}
	if ip != "" {
		if current := p.byIP[ip]; current != nil && current.Name == key {
			delete(p.byIP, ip)
		}
	}
	delete(p.ipByPod, key)
}

func buildIdentity(providerName string, pod *corev1.Pod) *Identity {
	return &Identity{
		Source:   "kubernetes",
		Provider: providerName,
		Name:     pod.Namespace + "/" + pod.Name,
		Labels:   labelsWithNamespace(pod.Namespace, pod.Labels),
	}
}

func labelsWithNamespace(namespace string, labels map[string]string) map[string]string {
	out := make(map[string]string, len(labels)+1)
	for key, value := range labels {
		out[key] = value
	}
	out["kubernetes.io/namespace"] = namespace
	return out
}

func cloneIdentity(id *Identity) *Identity {
	clone := &Identity{
		Source:   id.Source,
		Provider: id.Provider,
		Name:     id.Name,
		Labels:   make(map[string]string, len(id.Labels)),
	}
	for key, value := range id.Labels {
		clone.Labels[key] = value
	}
	return clone
}

func podFromObject(obj interface{}) *corev1.Pod {
	switch value := obj.(type) {
	case *corev1.Pod:
		return value
	case cache.DeletedFinalStateUnknown:
		pod, _ := value.Obj.(*corev1.Pod)
		return pod
	default:
		return nil
	}
}

func (p *KubernetesProvider) upsertPod(pod *corev1.Pod, previousIP string) {
	key := podKey(pod)
	newIP := pod.Status.PodIP

	p.mu.Lock()
	defer p.mu.Unlock()

	oldIP := p.ipByPod[key]
	if oldIP == "" {
		oldIP = previousIP
	}
	if oldIP != "" && oldIP != newIP {
		if current := p.byIP[oldIP]; current != nil && current.Name == key {
			delete(p.byIP, oldIP)
		}
	}
	if newIP == "" {
		delete(p.ipByPod, key)
		return
	}

	p.byIP[newIP] = buildIdentity(p.name, pod)
	p.ipByPod[key] = newIP
}

func podKey(pod *corev1.Pod) string {
	return pod.Namespace + "/" + pod.Name
}

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (int, error) {
	return len(p), nil
}

type watchListSemanticsUnsupported struct{}

func (watchListSemanticsUnsupported) IsWatchListSemanticsUnSupported() bool {
	return true
}
