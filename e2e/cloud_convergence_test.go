//go:build cloud_e2e

package e2e

import "testing"

func TestCloudLabelAndPolicyConvergence(t *testing.T) {
	h := newCloudHarness(t)
	h.ensureClientWorkload(t, map[string]string{"app": "wrong-client"})
	h.putPolicyFixture(t, "allow-http.yaml", h.allowHTTPPolicyYAML("sample-client", []string{h.namespace}))

	h.requireHTTPDenied(t, "/static/allowed")
	h.patchClientLabels(t, map[string]string{"app": "sample-client"})
	h.requireHTTPAllowed(t, "/static/allowed")
	h.patchClientLabels(t, map[string]string{"app": "wrong-client"})
	h.requireHTTPDenied(t, "/static/allowed")
}
