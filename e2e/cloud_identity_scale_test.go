//go:build cloud_e2e

package e2e

import "testing"

func TestCloudPodScaleAndRestartPropagates(t *testing.T) {
	h := newCloudHarness(t)
	h.putPolicyFixture(t, "allow-http.yaml", h.allowHTTPPolicyYAML("sample-client", []string{h.namespace}))
	h.ensureClientWorkload(t, map[string]string{"app": "sample-client"})

	h.requireHTTPAllowed(t, "/static/allowed")
	h.scaleClientDeployment(t, 3)
	h.requireAllClientPodsAllowed(t, "/static/allowed")

	previousPodIPs := h.clientPodIPs(t)
	h.scaleClientDeployment(t, 1)
	h.requireRemovedPodIPsDrained(t, previousPodIPs)

	h.restartClientDeployment(t)
	h.requireHTTPAllowed(t, "/static/allowed")
}
