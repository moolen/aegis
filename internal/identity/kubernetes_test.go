package identity

import (
	"context"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
)

func TestKubernetesProviderResolvesCreatedPod(t *testing.T) {
	source := newFakePodSource()
	provider, err := NewKubernetesProvider(KubernetesProviderConfig{
		Name:         "cluster-a",
		Source:       source,
		Namespaces:   []string{"default"},
		ResyncPeriod: time.Second,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewKubernetesProvider() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := provider.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	source.CreatePod(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "web",
			Namespace: "default",
			Labels:    map[string]string{"app": "web"},
		},
		Status: corev1.PodStatus{
			PodIP: "10.0.0.10",
		},
	})

	id := requireEventuallyIdentity(t, provider, "10.0.0.10")
	if id.Source != "kubernetes" {
		t.Fatalf("identity source = %q, want %q", id.Source, "kubernetes")
	}
	if id.Provider != "cluster-a" {
		t.Fatalf("identity provider = %q, want %q", id.Provider, "cluster-a")
	}
	if id.Name != "default/web" {
		t.Fatalf("identity name = %q, want %q", id.Name, "default/web")
	}
}

func TestKubernetesProviderReturnsNilForUnknownIP(t *testing.T) {
	source := newFakePodSource()
	provider, err := NewKubernetesProvider(KubernetesProviderConfig{
		Name:         "cluster-a",
		Source:       source,
		ResyncPeriod: time.Second,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewKubernetesProvider() error = %v", err)
	}

	id, err := provider.Resolve(net.ParseIP("10.0.0.44"))
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if id != nil {
		t.Fatalf("Resolve() identity = %#v, want nil", id)
	}
}

func requireEventuallyIdentity(t *testing.T, provider *KubernetesProvider, ip string) *Identity {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		id, err := provider.Resolve(net.ParseIP(ip))
		if err != nil {
			t.Fatalf("Resolve() error = %v", err)
		}
		if id != nil {
			return id
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("Resolve(%q) never returned an identity", ip)
	return nil
}

type fakePodSource struct {
	mu         sync.Mutex
	pods       map[string]map[string]*corev1.Pod
	namespaces map[string]*fakePodNamespaceClient
}

func newFakePodSource() *fakePodSource {
	return &fakePodSource{
		pods:       make(map[string]map[string]*corev1.Pod),
		namespaces: make(map[string]*fakePodNamespaceClient),
	}
}

func (s *fakePodSource) Pods(namespace string) KubernetesPodNamespaceClient {
	s.mu.Lock()
	defer s.mu.Unlock()

	client := s.namespaces[namespace]
	if client != nil {
		return client
	}

	client = &fakePodNamespaceClient{
		namespace: namespace,
		source:    s,
		watcher:   watch.NewRaceFreeFake(),
	}
	s.namespaces[namespace] = client
	return client
}

func (s *fakePodSource) CreatePod(pod *corev1.Pod) {
	s.mu.Lock()
	defer s.mu.Unlock()

	namespace := pod.Namespace
	if namespace == "" {
		namespace = metav1.NamespaceDefault
	}
	if s.pods[namespace] == nil {
		s.pods[namespace] = make(map[string]*corev1.Pod)
	}

	copy := pod.DeepCopy()
	s.pods[namespace][copy.Name] = copy

	client := s.ensureNamespaceClientLocked(namespace)
	client.watcher.Add(copy.DeepCopy())
}

func (s *fakePodSource) listPods(namespace string) *corev1.PodList {
	s.mu.Lock()
	defer s.mu.Unlock()

	list := &corev1.PodList{}
	if namespace == metav1.NamespaceAll {
		for _, pods := range s.pods {
			for _, pod := range pods {
				list.Items = append(list.Items, *pod.DeepCopy())
			}
		}
		return list
	}

	for _, pod := range s.pods[namespace] {
		list.Items = append(list.Items, *pod.DeepCopy())
	}
	return list
}

func (s *fakePodSource) ensureNamespaceClientLocked(namespace string) *fakePodNamespaceClient {
	client := s.namespaces[namespace]
	if client != nil {
		return client
	}

	client = &fakePodNamespaceClient{
		namespace: namespace,
		source:    s,
		watcher:   watch.NewRaceFreeFake(),
	}
	s.namespaces[namespace] = client
	return client
}

type fakePodNamespaceClient struct {
	namespace string
	source    *fakePodSource
	watcher   *watch.RaceFreeFakeWatcher
}

func (c *fakePodNamespaceClient) List(context.Context, metav1.ListOptions) (*corev1.PodList, error) {
	return c.source.listPods(c.namespace), nil
}

func (c *fakePodNamespaceClient) Watch(context.Context, metav1.ListOptions) (watch.Interface, error) {
	return c.watcher, nil
}
