package proxy

import (
	"fmt"
	"log/slog"
	"sync"

	"github.com/moolen/aegis/internal/identity"
	"github.com/moolen/aegis/internal/metrics"
)

type ConnectionLimiter struct {
	logger  *slog.Logger
	metrics *metrics.Metrics

	mu     sync.Mutex
	limit  int
	active map[string]int
}

type ErrConnectionLimitExceeded struct {
	Identity string
	Active   int
	Limit    int
}

func (e *ErrConnectionLimitExceeded) Error() string {
	return fmt.Sprintf("identity %q exceeds concurrent connection limit: active=%d limit=%d", e.Identity, e.Active, e.Limit)
}

func NewConnectionLimiter(logger *slog.Logger, m *metrics.Metrics) *ConnectionLimiter {
	if logger == nil {
		logger = slog.Default()
	}
	return &ConnectionLimiter{
		logger:  logger,
		metrics: m,
		active:  make(map[string]int),
	}
}

func (l *ConnectionLimiter) UpdateLimit(limit int) {
	if l == nil {
		return
	}

	l.mu.Lock()
	l.limit = limit
	l.mu.Unlock()

	if l.metrics != nil {
		l.metrics.IdentityConnectionLimit.Set(float64(limit))
	}
}

func (l *ConnectionLimiter) Limit() int {
	if l == nil {
		return 0
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	return l.limit
}

func (l *ConnectionLimiter) Enabled() bool {
	return l.Limit() > 0
}

func (l *ConnectionLimiter) Acquire(id *identity.Identity, protocol string) (func(), error) {
	if l == nil {
		return func() {}, nil
	}

	identityName := normalizeIdentityName(id)

	l.mu.Lock()
	limit := l.limit
	current := l.active[identityName]
	if limit > 0 && current >= limit {
		l.mu.Unlock()
		l.recordRejected(protocol)
		l.logger.Warn("identity concurrent connection limit exceeded",
			"protocol", protocol,
			"identity_name", identityName,
			"active_connections", current,
			"connection_limit", limit,
		)
		return nil, &ErrConnectionLimitExceeded{
			Identity: identityName,
			Active:   current,
			Limit:    limit,
		}
	}

	l.active[identityName] = current + 1
	l.mu.Unlock()
	l.recordActive(protocol, 1)

	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			next := l.active[identityName] - 1
			if next <= 0 {
				delete(l.active, identityName)
			} else {
				l.active[identityName] = next
			}
			l.mu.Unlock()
			l.recordActive(protocol, -1)
		})
	}, nil
}

func (l *ConnectionLimiter) recordActive(protocol string, delta float64) {
	if l == nil || l.metrics == nil {
		return
	}
	l.metrics.IdentityConnectionsActive.WithLabelValues(protocol).Add(delta)
}

func (l *ConnectionLimiter) recordRejected(protocol string) {
	if l == nil || l.metrics == nil {
		return
	}
	l.metrics.IdentityConnectionLimitRejectionsTotal.WithLabelValues(protocol).Inc()
}
