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

	appmetrics "github.com/moolen/aegis/internal/metrics"
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
	metrics   *appmetrics.Metrics

	mu           sync.RWMutex
	byIP         map[string]*Identity
	ipByPod      map[string]string
	sources      map[string]*kubernetesSourceStatus
	started      bool
	lifecycleCtx context.Context
	runCancel    context.CancelFunc
}

type kubernetesSourceStatus struct {
	lastSuccess   time.Time
	activeWatches int
	lastError     time.Time
	lastErrorText string
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
		sources: make(map[string]*kubernetesSourceStatus),
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
		provider.sources[namespace] = &kubernetesSourceStatus{}
		source := cfg.Source.Pods(namespace)
		namespaceKey := namespace
		listWatch := &cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				obj, err := source.List(provider.runContext(), options)
				if err != nil {
					provider.recordSourceFailure(namespaceKey, err)
					return nil, err
				}
				provider.recordSourceListSuccess(namespaceKey)
				return obj, nil
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				watcher, err := source.Watch(provider.runContext(), options)
				if err != nil {
					provider.recordSourceFailure(namespaceKey, err)
					return nil, err
				}
				provider.recordSourceWatchEstablished(namespaceKey)
				return newStatusTrackingWatch(watcher, func() {
					provider.recordSourceWatchClosed(namespaceKey)
				}), nil
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

func (p *KubernetesProvider) Start(ctx context.Context, startupTimeout time.Duration) error {
	p.mu.Lock()
	if p.started {
		p.mu.Unlock()
		return nil
	}

	runCtx, runCancel := context.WithCancel(ctx)
	p.started = true
	p.lifecycleCtx = runCtx
	p.runCancel = runCancel
	p.mu.Unlock()

	go p.runStatusReporter(runCtx)
	for _, informer := range p.informers {
		go informer.Run(runCtx.Done())
	}

	hasSynced := make([]cache.InformerSynced, 0, len(p.informers))
	for _, informer := range p.informers {
		hasSynced = append(hasSynced, informer.HasSynced)
	}

	startupCtx := runCtx
	cancelStartup := func() {}
	if startupTimeout > 0 {
		startupCtxWithTimeout, cancel := context.WithTimeout(runCtx, startupTimeout)
		startupCtx = startupCtxWithTimeout
		cancelStartup = cancel
	}
	defer cancelStartup()

	if ok := cache.WaitForCacheSync(startupCtx.Done(), hasSynced...); !ok {
		runCancel()
		p.resetRunState()
		if err := startupCtx.Err(); err != nil {
			return fmt.Errorf("sync kubernetes provider caches: %w", err)
		}
		return fmt.Errorf("sync kubernetes provider caches")
	}

	p.reportMapSize()
	p.reportStatus()

	return nil
}

func (p *KubernetesProvider) AttachMetrics(m *appmetrics.Metrics) {
	p.mu.Lock()
	p.metrics = m
	p.mu.Unlock()
	p.reportMapSize()
	p.reportStatus()
}

func (p *KubernetesProvider) runContext() context.Context {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.lifecycleCtx == nil {
		return context.Background()
	}

	return p.lifecycleCtx
}

func (p *KubernetesProvider) resetRunState() {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.runCancel = nil
	p.lifecycleCtx = nil
	p.started = false
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

func (p *KubernetesProvider) ProviderStatus() ProviderStatus {
	p.mu.RLock()
	defer p.mu.RUnlock()

	status := ProviderStatus{
		Name:  p.name,
		Kind:  "kubernetes",
		State: ProviderStateActive,
	}
	now := time.Now()
	for namespace, sourceStatus := range p.sources {
		sourceState := p.evaluateSourceStateLocked(namespace, sourceStatus, now)
		if sourceState == ProviderStateDown {
			status.State = ProviderStateDown
			status.LastSuccess = sourceStatus.lastSuccess
			status.LastError = sourceStatus.lastError
			status.LastErrorMessage = sourceStatus.lastErrorText
			return status
		}
		if sourceState == ProviderStateStale {
			status.State = ProviderStateStale
			status.LastSuccess = sourceStatus.lastSuccess
			status.LastError = sourceStatus.lastError
			status.LastErrorMessage = sourceStatus.lastErrorText
		}
	}
	return status
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
	p.reportMapSizeLocked()
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
		p.reportMapSizeLocked()
		return
	}

	p.byIP[newIP] = buildIdentity(p.name, pod)
	p.ipByPod[key] = newIP
	p.reportMapSizeLocked()
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

func (p *KubernetesProvider) reportMapSize() {
	p.mu.RLock()
	defer p.mu.RUnlock()
	p.reportMapSizeLocked()
}

func (p *KubernetesProvider) reportMapSizeLocked() {
	if p.metrics == nil {
		return
	}
	p.metrics.IdentityMapEntries.WithLabelValues(p.name, "kubernetes").Set(float64(len(p.byIP)))
}

func (p *KubernetesProvider) recordSourceListSuccess(namespace string) {
	p.mu.Lock()
	sourceStatus := p.ensureSourceStatusLocked(namespace)
	sourceStatus.lastSuccess = time.Now()
	sourceStatus.lastError = time.Time{}
	sourceStatus.lastErrorText = ""
	p.mu.Unlock()
	p.reportStatus()
}

func (p *KubernetesProvider) recordSourceWatchEstablished(namespace string) {
	p.mu.Lock()
	sourceStatus := p.ensureSourceStatusLocked(namespace)
	sourceStatus.lastSuccess = time.Now()
	sourceStatus.activeWatches++
	sourceStatus.lastError = time.Time{}
	sourceStatus.lastErrorText = ""
	p.mu.Unlock()
	p.reportStatus()
}

func (p *KubernetesProvider) recordSourceWatchClosed(namespace string) {
	p.mu.Lock()
	sourceStatus := p.ensureSourceStatusLocked(namespace)
	if sourceStatus.activeWatches > 0 {
		sourceStatus.activeWatches--
	}
	p.mu.Unlock()
	p.reportStatus()
}

func (p *KubernetesProvider) recordSourceFailure(namespace string, err error) {
	p.mu.Lock()
	sourceStatus := p.ensureSourceStatusLocked(namespace)
	sourceStatus.lastError = time.Now()
	if err != nil {
		sourceStatus.lastErrorText = err.Error()
	}
	p.mu.Unlock()
	p.reportStatus()
}

func (p *KubernetesProvider) ensureSourceStatusLocked(namespace string) *kubernetesSourceStatus {
	sourceStatus := p.sources[namespace]
	if sourceStatus == nil {
		sourceStatus = &kubernetesSourceStatus{}
		p.sources[namespace] = sourceStatus
	}
	return sourceStatus
}

func (p *KubernetesProvider) evaluateSourceStateLocked(_ string, sourceStatus *kubernetesSourceStatus, now time.Time) string {
	if sourceStatus == nil {
		return ProviderStateDown
	}
	if sourceStatus.activeWatches > 0 {
		return ProviderStateActive
	}
	return EvaluateProviderState(sourceStatus.lastSuccess, now)
}

func (p *KubernetesProvider) runStatusReporter(ctx context.Context) {
	interval := ProviderStatusRefreshInterval
	if interval <= 0 {
		return
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.reportStatus()
		}
	}
}

func (p *KubernetesProvider) reportStatus() {
	p.mu.RLock()
	metrics := p.metrics
	p.mu.RUnlock()
	if metrics == nil {
		return
	}

	status := p.ProviderStatus()
	for _, state := range []string{ProviderStateActive, ProviderStateStale, ProviderStateDown} {
		value := 0.0
		if status.State == state {
			value = 1
		}
		metrics.IdentityProviderStatus.WithLabelValues(p.name, "kubernetes", state).Set(value)
	}

	lastSuccess := 0.0
	if !status.LastSuccess.IsZero() {
		lastSuccess = float64(status.LastSuccess.Unix())
	}
	metrics.IdentityProviderLastSuccess.WithLabelValues(p.name, "kubernetes").Set(lastSuccess)
}

type statusTrackingWatch struct {
	inner   watch.Interface
	onClose func()
	result  chan watch.Event
	once    sync.Once
}

func newStatusTrackingWatch(inner watch.Interface, onClose func()) watch.Interface {
	w := &statusTrackingWatch{
		inner:   inner,
		onClose: onClose,
		result:  make(chan watch.Event),
	}

	go func() {
		defer close(w.result)
		defer w.close()
		for event := range inner.ResultChan() {
			w.result <- event
		}
	}()

	return w
}

func (w *statusTrackingWatch) Stop() {
	w.inner.Stop()
	w.close()
}

func (w *statusTrackingWatch) ResultChan() <-chan watch.Event {
	return w.result
}

func (w *statusTrackingWatch) close() {
	w.once.Do(func() {
		if w.onClose != nil {
			w.onClose()
		}
	})
}
