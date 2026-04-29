//go:build cloud_e2e

package e2e

import "testing"

func TestCloudNamespaceScopePropagates(t *testing.T) {
	h := newCloudHarness(t)
	other := h.newSiblingNamespace(t)

	h.ensureClientWorkload(t, map[string]string{"app": "sample-client"})
	other.ensureClientWorkload(t, map[string]string{"app": "sample-client"})

	h.putPolicyFixture(t, "allow-http.yaml", h.allowHTTPPolicyYAML("sample-client", []string{h.namespace}))
	h.requireHTTPAllowed(t, "/static/allowed")
	other.requireHTTPDenied(t, "/static/allowed")

	h.putPolicyFixture(t, "allow-http.yaml", h.allowHTTPPolicyYAML("sample-client", []string{h.namespace, other.namespace}))
	other.requireHTTPAllowed(t, "/static/allowed")
}
