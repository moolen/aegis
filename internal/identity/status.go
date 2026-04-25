package identity

import (
	"fmt"
	"strings"
	"time"
)

var ProviderStaleAfter = 5 * time.Minute
var ProviderDownAfter = 15 * time.Minute
var ProviderStatusRefreshInterval = 30 * time.Second

const (
	ProviderStateActive = "active"
	ProviderStateStale  = "stale"
	ProviderStateDown   = "down"
)

type ProviderStatus struct {
	Name             string
	Kind             string
	State            string
	LastSuccess      time.Time
	LastError        time.Time
	LastErrorMessage string
}

type StatusReporter interface {
	ProviderStatus() ProviderStatus
}

func EvaluateProviderState(lastSuccess time.Time, now time.Time) string {
	if lastSuccess.IsZero() {
		return ProviderStateDown
	}

	age := now.Sub(lastSuccess)
	if age > ProviderDownAfter {
		return ProviderStateDown
	}
	if age > ProviderStaleAfter {
		return ProviderStateStale
	}
	return ProviderStateActive
}

func ReadinessError(statuses []ProviderStatus) error {
	if len(statuses) == 0 {
		return nil
	}

	active := 0
	parts := make([]string, 0, len(statuses))
	for _, status := range statuses {
		if status.State == "" {
			status.State = ProviderStateActive
		}
		if status.State == ProviderStateActive {
			active++
		}
		parts = append(parts, fmt.Sprintf("%s/%s=%s", status.Kind, status.Name, status.State))
	}
	if active > 0 {
		return nil
	}

	return fmt.Errorf("no active discovery providers: %s", strings.Join(parts, ", "))
}
