//go:build e2e || kind_e2e

package e2e

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

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
