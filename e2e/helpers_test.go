//go:build e2e || kind_e2e || cloud_e2e

package e2e

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"

	appmetrics "github.com/moolen/aegis/internal/metrics"
)

const (
	defaultE2EEC2ProviderName = "local-ec2"
	defaultE2EEC2TagKey       = "aegis-test"
	defaultE2EEC2TagValue     = "local"
)

type fakeEC2Instance struct {
	InstanceID string
	PrivateIP  string
	Tags       map[string]string
}

type fakeKubernetesPod struct {
	Namespace string
	Name      string
	IP        string
	Labels    map[string]string
}

type deploymentStatus struct {
	Metadata struct {
		Generation int64 `json:"generation"`
	} `json:"metadata"`
	Spec struct {
		Replicas *int32 `json:"replicas"`
	} `json:"spec"`
	Status struct {
		ObservedGeneration  int64             `json:"observedGeneration"`
		Replicas            int32             `json:"replicas"`
		UpdatedReplicas     int32             `json:"updatedReplicas"`
		ReadyReplicas       int32             `json:"readyReplicas"`
		AvailableReplicas   int32             `json:"availableReplicas"`
		UnavailableReplicas int32             `json:"unavailableReplicas"`
		Conditions          []statusCondition `json:"conditions"`
	} `json:"status"`
}

type statusCondition struct {
	Type   string `json:"type"`
	Status string `json:"status"`
}

type ec2QueryFilter struct {
	Name   string
	Values []string
}

type describeInstancesResponse struct {
	XMLName        xml.Name                  `xml:"DescribeInstancesResponse"`
	XMLNS          string                    `xml:"xmlns,attr"`
	RequestID      string                    `xml:"requestId"`
	ReservationSet describeReservationSetXML `xml:"reservationSet"`
}

type describeReservationSetXML struct {
	Items []describeReservationXML `xml:"item"`
}

type describeReservationXML struct {
	ReservationID string                  `xml:"reservationId"`
	InstancesSet  describeInstancesSetXML `xml:"instancesSet"`
}

type describeInstancesSetXML struct {
	Items []describeInstanceXML `xml:"item"`
}

type describeInstanceXML struct {
	InstanceID       string            `xml:"instanceId"`
	PrivateIPAddress string            `xml:"privateIpAddress"`
	TagSet           describeTagSetXML `xml:"tagSet"`
}

type describeTagSetXML struct {
	Items []describeTagXML `xml:"item"`
}

type describeTagXML struct {
	Key   string `xml:"key"`
	Value string `xml:"value"`
}

func metricValue(t *testing.T, metricsBody string, name string, labels map[string]string) float64 {
	t.Helper()

	value, ok := metricValueOrZero(metricsBody, name, labels)
	if ok {
		return value
	}

	t.Fatalf("metric %q with labels %#v not found", name, labels)
	return 0
}

func metricValueOrZero(metricsBody string, name string, labels map[string]string) (float64, bool) {
	for _, line := range strings.Split(metricsBody, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		metricName, metricLabels, value, ok := parseMetricLine(line)
		if !ok || metricName != name {
			continue
		}
		if labelsEqual(metricLabels, labels) {
			return value, true
		}
	}

	return 0, false
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}

	t.Fatal("condition not satisfied before timeout")
}

func parseMetricLine(line string) (string, map[string]string, float64, bool) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return "", nil, 0, false
	}

	nameAndLabels := fields[0]
	value, err := strconv.ParseFloat(fields[len(fields)-1], 64)
	if err != nil {
		return "", nil, 0, false
	}

	if !strings.Contains(nameAndLabels, "{") {
		return nameAndLabels, map[string]string{}, value, true
	}

	open := strings.IndexByte(nameAndLabels, '{')
	close := strings.LastIndexByte(nameAndLabels, '}')
	if open < 0 || close < open {
		return "", nil, 0, false
	}

	name := nameAndLabels[:open]
	labelsText := nameAndLabels[open+1 : close]
	labels := make(map[string]string)
	if labelsText != "" {
		for _, pair := range strings.Split(labelsText, ",") {
			key, rawValue, ok := strings.Cut(pair, "=")
			if !ok {
				return "", nil, 0, false
			}
			labels[key] = strings.Trim(rawValue, `"`)
		}
	}

	return name, labels, value, true
}

func labelsEqual(got map[string]string, want map[string]string) bool {
	if len(got) != len(want) {
		return false
	}
	for key, value := range want {
		if got[key] != value {
			return false
		}
	}
	return true
}

func mergeEnvVars(base []string, overlays ...[]string) []string {
	orderedKeys := make([]string, 0, len(base))
	values := make(map[string]string, len(base))

	for _, env := range base {
		key, value, ok := strings.Cut(env, "=")
		if !ok {
			continue
		}
		if _, seen := values[key]; !seen {
			orderedKeys = append(orderedKeys, key)
		}
		values[key] = value
	}

	for _, overlay := range overlays {
		for _, env := range overlay {
			key, value, ok := strings.Cut(env, "=")
			if !ok {
				continue
			}
			if _, seen := values[key]; !seen {
				orderedKeys = append(orderedKeys, key)
			}
			values[key] = value
		}
	}

	merged := make([]string, 0, len(orderedKeys))
	for _, key := range orderedKeys {
		merged = append(merged, key+"="+values[key])
	}
	return merged
}

func mustRepoRoot(t *testing.T) string {
	t.Helper()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd() error = %v", err)
	}

	return filepath.Dir(wd)
}

func runCommand(t *testing.T, dir string, timeout time.Duration, name string, args ...string) string {
	t.Helper()

	output, err := runCommandOutput(dir, timeout, name, args...)
	if err != nil {
		t.Fatalf("%s %s failed: %v\n%s", name, strings.Join(args, " "), err, output)
	}

	return output
}

func runBestEffort(dir string, timeout time.Duration, name string, args ...string) {
	_, _ = runCommandOutput(dir, timeout, name, args...)
}

func runCommandOutput(dir string, timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	output, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return string(output), fmt.Errorf("command timed out after %s", timeout)
	}
	if err != nil {
		return string(output), err
	}

	return string(output), nil
}

func kubectlApplyYAML(t *testing.T, repoRoot string, kubeContext string, namespace string, manifest string) {
	t.Helper()

	manifestPath := filepath.Join(t.TempDir(), "manifest.yaml")
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o644); err != nil {
		t.Fatalf("WriteFile(manifest) error = %v", err)
	}

	runCommand(t, repoRoot, 2*time.Minute, "kubectl", "--context", kubeContext, "-n", namespace, "apply", "-f", manifestPath)
}

func waitForDeploymentAvailable(t *testing.T, repoRoot string, kubeContext string, namespace string, name string, timeout time.Duration) {
	t.Helper()

	waitFor(t, timeout, func() bool {
		output, err := runCommandOutput(repoRoot, 15*time.Second, "kubectl", "--context", kubeContext, "-n", namespace, "get", "deployment", name, "-o", "json")
		if err != nil {
			return false
		}

		var status deploymentStatus
		if err := json.Unmarshal([]byte(output), &status); err != nil {
			return false
		}

		replicas := int32(1)
		if status.Spec.Replicas != nil {
			replicas = *status.Spec.Replicas
		}

		return status.Status.ObservedGeneration >= status.Metadata.Generation &&
			status.Status.UpdatedReplicas == replicas &&
			status.Status.ReadyReplicas == replicas &&
			status.Status.AvailableReplicas == replicas &&
			status.Status.UnavailableReplicas == 0 &&
			conditionTrue(status.Status.Conditions, "Available")
	})
}

func podReady(conditions []statusCondition) bool {
	return conditionTrue(conditions, "Ready")
}

func conditionTrue(conditions []statusCondition, wantType string) bool {
	for _, condition := range conditions {
		if condition.Type == wantType && condition.Status == "True" {
			return true
		}
	}
	return false
}

func sanitizeDNSLabel(value string) string {
	value = strings.ToLower(value)

	var b strings.Builder
	b.Grow(len(value))
	lastHyphen := false
	for _, r := range value {
		isAlphaNum := r >= 'a' && r <= 'z' || r >= '0' && r <= '9'
		if isAlphaNum {
			b.WriteRune(r)
			lastHyphen = false
			continue
		}
		if !lastHyphen && b.Len() > 0 {
			b.WriteByte('-')
			lastHyphen = true
		}
	}

	return strings.Trim(b.String(), "-")
}

func buildDNSLabel(prefix string, slug string, suffix string, maxLen int) string {
	parts := []string{prefix}
	if slug != "" {
		parts = append(parts, slug)
	}
	if suffix != "" {
		parts = append(parts, suffix)
	}

	label := strings.Join(parts, "-")
	if len(label) <= maxLen {
		return label
	}

	trimmedSlugLen := maxLen - len(prefix) - len(suffix) - 2
	if trimmedSlugLen < 1 {
		trimmedSlugLen = 1
	}
	if len(slug) > trimmedSlugLen {
		slug = strings.Trim(slug[:trimmedSlugLen], "-")
		if slug == "" {
			slug = "x"
		}
	}

	return strings.Join([]string{prefix, slug, suffix}, "-")
}

func startFakeEC2APIServer(t *testing.T, instances []fakeEC2Instance) *httptest.Server {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		params, err := ec2QueryParams(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if params.Get("Action") != "DescribeInstances" {
			http.Error(w, "unsupported action", http.StatusBadRequest)
			return
		}

		filters := ec2FiltersFromQuery(params)
		response := describeInstancesResponse{
			XMLNS:     "http://ec2.amazonaws.com/doc/2016-11-15/",
			RequestID: "req-e2e",
		}
		for index, instance := range instances {
			if !matchesEC2Filters(instance, filters) {
				continue
			}
			response.ReservationSet.Items = append(response.ReservationSet.Items, describeReservationXML{
				ReservationID: fmt.Sprintf("r-%d", index+1),
				InstancesSet: describeInstancesSetXML{
					Items: []describeInstanceXML{{
						InstanceID:       instance.InstanceID,
						PrivateIPAddress: instance.PrivateIP,
						TagSet:           ec2TagSetXML(instance.Tags),
					}},
				},
			})
		}

		w.Header().Set("Content-Type", "text/xml")
		if err := xml.NewEncoder(w).Encode(response); err != nil {
			t.Logf("encode fake ec2 response: %v", err)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func defaultFakeEC2Env(t *testing.T) []string {
	t.Helper()

	server := startFakeEC2APIServer(t, []fakeEC2Instance{{
		InstanceID: "i-localhost",
		PrivateIP:  "127.0.0.1",
		Tags: map[string]string{
			defaultE2EEC2TagKey: defaultE2EEC2TagValue,
		},
	}})
	return fakeEC2Env(server.URL)
}

func fakeEC2Env(endpoint string) []string {
	return []string{
		"AWS_ACCESS_KEY_ID=test",
		"AWS_SECRET_ACCESS_KEY=test",
		"AWS_REGION=us-east-1",
		"AWS_EC2_METADATA_DISABLED=true",
		"AWS_ENDPOINT_URL_EC2=" + endpoint,
	}
}

func ec2QueryParams(r *http.Request) (url.Values, error) {
	params := url.Values{}
	for key, values := range r.URL.Query() {
		for _, value := range values {
			params.Add(key, value)
		}
	}
	if r.Method == http.MethodPost {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		values, err := url.ParseQuery(string(body))
		if err != nil {
			return nil, err
		}
		for key, valueList := range values {
			for _, value := range valueList {
				params.Add(key, value)
			}
		}
	}
	return params, nil
}

func ec2FiltersFromQuery(values url.Values) []ec2QueryFilter {
	byIndex := make(map[string]*ec2QueryFilter)
	for key, list := range values {
		parts := strings.Split(key, ".")
		if len(parts) < 3 || parts[0] != "Filter" {
			continue
		}
		filter := byIndex[parts[1]]
		if filter == nil {
			filter = &ec2QueryFilter{}
			byIndex[parts[1]] = filter
		}
		switch parts[2] {
		case "Name":
			filter.Name = firstOrEmpty(list)
		case "Value":
			filter.Values = append(filter.Values, list...)
		}
	}

	indexes := make([]string, 0, len(byIndex))
	for index := range byIndex {
		indexes = append(indexes, index)
	}
	sort.Strings(indexes)

	filters := make([]ec2QueryFilter, 0, len(indexes))
	for _, index := range indexes {
		filters = append(filters, *byIndex[index])
	}
	return filters
}

func matchesEC2Filters(instance fakeEC2Instance, filters []ec2QueryFilter) bool {
	for _, filter := range filters {
		if !matchesEC2Filter(instance, filter) {
			return false
		}
	}
	return true
}

func matchesEC2Filter(instance fakeEC2Instance, filter ec2QueryFilter) bool {
	if !strings.HasPrefix(filter.Name, "tag:") {
		return true
	}

	tagKey := strings.TrimPrefix(filter.Name, "tag:")
	tagValue := instance.Tags[tagKey]
	if len(filter.Values) == 0 {
		return tagValue != ""
	}
	for _, value := range filter.Values {
		if tagValue == value {
			return true
		}
	}
	return false
}

func ec2TagSetXML(tags map[string]string) describeTagSetXML {
	keys := make([]string, 0, len(tags))
	for key := range tags {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	out := describeTagSetXML{Items: make([]describeTagXML, 0, len(keys))}
	for _, key := range keys {
		out.Items = append(out.Items, describeTagXML{Key: key, Value: tags[key]})
	}
	return out
}

func firstOrEmpty(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func startFakeKubernetesAPIServer(t *testing.T, pods []fakeKubernetesPod) *httptest.Server {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		namespace, ok := kubernetesNamespaceFromPath(r.URL.Path)
		if !ok {
			http.NotFound(w, r)
			return
		}

		namespacePods := make([]fakeKubernetesPod, 0, len(pods))
		for _, pod := range pods {
			if pod.Namespace == namespace {
				namespacePods = append(namespacePods, pod)
			}
		}

		if r.URL.Query().Get("watch") == "true" || r.URL.Query().Get("watch") == "1" {
			fakeKubernetesWatchResponse(t, w, r, namespacePods)
			return
		}

		list := &corev1.PodList{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "v1",
				Kind:       "PodList",
			},
			ListMeta: metav1.ListMeta{ResourceVersion: "1"},
		}
		for _, pod := range namespacePods {
			list.Items = append(list.Items, fakeCorePod(pod))
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(list); err != nil {
			t.Logf("encode fake kubernetes list: %v", err)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func fakeKubernetesWatchResponse(t *testing.T, w http.ResponseWriter, r *http.Request, pods []fakeKubernetesPod) {
	t.Helper()

	flusher, ok := w.(http.Flusher)
	if !ok {
		t.Fatal("fake kubernetes watch response does not support flushing")
	}

	w.Header().Set("Content-Type", "application/json")
	encoder := json.NewEncoder(w)
	for _, pod := range pods {
		podObj := fakeCorePod(pod)
		event := watch.Event{
			Type:   watch.Added,
			Object: &podObj,
		}
		if err := encoder.Encode(event); err != nil {
			t.Logf("encode fake kubernetes watch event: %v", err)
			return
		}
		flusher.Flush()
	}

	<-r.Context().Done()
}

func fakeCorePod(pod fakeKubernetesPod) corev1.Pod {
	return corev1.Pod{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Pod",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      pod.Name,
			Namespace: pod.Namespace,
			Labels:    cloneLabels(pod.Labels),
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			PodIP: pod.IP,
		},
	}
}

func kubernetesNamespaceFromPath(path string) (string, bool) {
	const prefix = "/api/v1/namespaces/"
	if !strings.HasPrefix(path, prefix) || !strings.HasSuffix(path, "/pods") {
		return "", false
	}

	remainder := strings.TrimPrefix(path, prefix)
	namespace, _, ok := strings.Cut(remainder, "/pods")
	if !ok || namespace == "" {
		return "", false
	}
	return namespace, true
}

func writeKubeconfig(t *testing.T, serverURL string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "kubeconfig")
	contents := fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
  - name: fake
    cluster:
      server: %q
contexts:
  - name: fake
    context:
      cluster: fake
      user: fake
current-context: fake
users:
  - name: fake
    user:
      token: fake-token
`, serverURL)
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("WriteFile(kubeconfig) error = %v", err)
	}
	return path
}

func simulateRequest(t *testing.T, baseURL string, token string, req appmetrics.SimulationRequest) appmetrics.SimulationResponse {
	t.Helper()

	query := url.Values{
		"sourceIP": []string{req.SourceIP},
		"fqdn":     []string{req.FQDN},
		"port":     []string{strconv.Itoa(req.Port)},
		"protocol": []string{req.Protocol},
	}
	if req.Method != "" {
		query.Set("method", req.Method)
	}
	if req.Path != "" {
		query.Set("path", req.Path)
	}

	httpReq, err := http.NewRequest(http.MethodGet, baseURL+"/admin/simulate?"+query.Encode(), nil)
	if err != nil {
		t.Fatalf("NewRequest(simulate) error = %v", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		t.Fatalf("simulate request error = %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("simulate status = %d, want %d: %s", resp.StatusCode, http.StatusOK, string(body))
	}

	var out appmetrics.SimulationResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("Decode(simulate) error = %v", err)
	}
	return out
}

func fetchAdminIdentities(t *testing.T, baseURL string, token string) []appmetrics.IdentityDumpRecord {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, baseURL+"/admin/identities", nil)
	if err != nil {
		t.Fatalf("NewRequest(identities) error = %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /admin/identities error = %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("/admin/identities status = %d, want %d: %s", resp.StatusCode, http.StatusOK, string(body))
	}

	var records []appmetrics.IdentityDumpRecord
	if err := json.NewDecoder(resp.Body).Decode(&records); err != nil {
		t.Fatalf("Decode(identities) error = %v", err)
	}
	return records
}

func waitForIdentityProviders(t *testing.T, baseURL string, token string, providers ...string) {
	t.Helper()

	want := make(map[string]struct{}, len(providers))
	for _, provider := range providers {
		want[provider] = struct{}{}
	}

	waitFor(t, 5*time.Second, func() bool {
		records := fetchAdminIdentities(t, baseURL, token)
		seen := make(map[string]struct{}, len(records))
		for _, record := range records {
			if record.Effective != nil {
				seen[record.Effective.Provider] = struct{}{}
			}
		}
		for provider := range want {
			if _, ok := seen[provider]; !ok {
				return false
			}
		}
		return true
	})
}

func cloneLabels(labels map[string]string) map[string]string {
	out := make(map[string]string, len(labels))
	for key, value := range labels {
		out[key] = value
	}
	return out
}
