package identity

import (
	"errors"
	"fmt"
	"log/slog"
	"net"

	"github.com/moolen/aegis/internal/metrics"
)

type ProviderHandle struct {
	Name     string
	Kind     string
	Resolver Resolver
}

type CompositeResolver struct {
	providers []ProviderHandle
	logger    *slog.Logger
	metrics   *metrics.Metrics
}

func NewCompositeResolver(providers []ProviderHandle, logger *slog.Logger, m *metrics.Metrics) *CompositeResolver {
	if logger == nil {
		logger = slog.Default()
	}

	return &CompositeResolver{
		providers: providers,
		logger:    logger,
		metrics:   m,
	}
}

func (r *CompositeResolver) Resolve(ip net.IP) (*Identity, error) {
	var winner *Identity
	var winnerProvider ProviderHandle

	for _, provider := range r.providers {
		if provider.Resolver == nil {
			err := errors.New("identity resolver is nil")
			r.logger.Warn("identity resolve failed", "provider", provider.Name, "kind", provider.Kind, "ip", ip.String(), "error", err)
			if r.metrics != nil {
				r.metrics.IdentityResolutionsTotal.WithLabelValues(provider.Name, provider.Kind, "error").Inc()
			}
			continue
		}

		id, err := provider.Resolver.Resolve(ip)
		if err != nil {
			r.logger.Warn("identity resolve failed", "provider", provider.Name, "kind", provider.Kind, "ip", ip.String(), "error", err)
			if r.metrics != nil {
				r.metrics.IdentityResolutionsTotal.WithLabelValues(provider.Name, provider.Kind, "error").Inc()
			}
			continue
		}

		if id == nil {
			if r.metrics != nil {
				r.metrics.IdentityResolutionsTotal.WithLabelValues(provider.Name, provider.Kind, "miss").Inc()
			}
			continue
		}

		if r.metrics != nil {
			r.metrics.IdentityResolutionsTotal.WithLabelValues(provider.Name, provider.Kind, "hit").Inc()
		}

		if winner == nil {
			winner = id
			winnerProvider = provider
			continue
		}

		r.logger.Warn(
			"identity overlap detected",
			"ip", ip.String(),
			"winner_provider", winnerProvider.Name,
			"winner_kind", winnerProvider.Kind,
			"shadow_provider", provider.Name,
			"shadow_kind", provider.Kind,
		)
		if r.metrics != nil {
			r.metrics.IdentityOverlapsTotal.WithLabelValues(
				winnerProvider.Name,
				winnerProvider.Kind,
				provider.Name,
				provider.Kind,
			).Inc()
		}
	}

	return winner, nil
}

func (r *CompositeResolver) ProviderStatuses() []ProviderStatus {
	statuses := make([]ProviderStatus, 0, len(r.providers))
	for _, provider := range r.providers {
		if reporter, ok := provider.Resolver.(StatusReporter); ok {
			status := reporter.ProviderStatus()
			if status.Name == "" {
				status.Name = provider.Name
			}
			if status.Kind == "" {
				status.Kind = provider.Kind
			}
			if status.State == "" {
				status.State = ProviderStateActive
			}
			statuses = append(statuses, status)
			continue
		}

		statuses = append(statuses, ProviderStatus{
			Name:  provider.Name,
			Kind:  provider.Kind,
			State: ProviderStateActive,
		})
	}
	return statuses
}

func (r *CompositeResolver) CheckReadiness() error {
	if err := ReadinessError(r.ProviderStatuses()); err != nil {
		return fmt.Errorf("discovery not ready: %w", err)
	}
	return nil
}
