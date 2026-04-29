//go:build cloud_e2e

package e2e

import "testing"

func TestCloudBlobPolicyLifecyclePropagates(t *testing.T) {
	h := newCloudHarness(t)
	h.ensureClientWorkload(t, map[string]string{"app": "sample-client"})

	h.requireHTTPDenied(t, "/static/allowed")

	h.putPolicyFixture(t, "allow-http.yaml", h.allowHTTPPolicyYAML("sample-client", []string{h.namespace}))
	h.requireHTTPAllowed(t, "/static/allowed")

	h.putPolicyFixture(t, "allow-http.yaml", h.allowHTTPPolicyYAML("sample-client", []string{h.namespace}, withAllowedPaths("/healthz")))
	h.requireHTTPDenied(t, "/static/allowed")
	h.requireHTTPAllowed(t, "/healthz")

	h.deletePolicyFixture(t, "allow-http.yaml")
	h.requireHTTPDenied(t, "/healthz")
}
