package identity

import (
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
