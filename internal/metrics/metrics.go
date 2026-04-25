package metrics

import "github.com/prometheus/client_golang/prometheus"

type Metrics struct {
	RequestsTotal                  *prometheus.CounterVec
	RequestDecisionsTotal          *prometheus.CounterVec
	AuditDecisionsTotal            *prometheus.CounterVec
	ErrorsTotal                    *prometheus.CounterVec
	RequestDuration                *prometheus.HistogramVec
	PolicyEvaluationDuration       *prometheus.HistogramVec
	DNSResolutionsTotal            *prometheus.CounterVec
	DNSDuration                    prometheus.Histogram
	DiscoveryProviderStartsTotal   *prometheus.CounterVec
	DiscoveryProviderFailuresTotal *prometheus.CounterVec
	DiscoveryProvidersActive       prometheus.Gauge
	IdentityMapEntries             *prometheus.GaugeVec
	IdentityResolutionsTotal       *prometheus.CounterVec
	IdentityOverlapsTotal          *prometheus.CounterVec
	ProxyProtocolConnectionsTotal  *prometheus.CounterVec
	ConfigReloadsTotal             *prometheus.CounterVec
	ConnectTunnelsTotal            *prometheus.CounterVec
	ConnectTunnelsActive           *prometheus.GaugeVec
	MITMCertificatesTotal          *prometheus.CounterVec
	MITMCACyclesTotal              *prometheus.CounterVec
	MITMCertificateCacheEntries    prometheus.Gauge
	MITMCertificateCacheEvictions  *prometheus.CounterVec
	ShutdownsTotal                 *prometheus.CounterVec
	ShutdownDuration               prometheus.Histogram
	ShutdownForcedTunnelCloses     *prometheus.CounterVec
	UpstreamTLSErrorsTotal         *prometheus.CounterVec
	TLSSNIMissingTotal             prometheus.Counter
}

func New(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		RequestsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "aegis_requests_total",
				Help: "Total number of proxied requests.",
			},
			[]string{"method", "protocol"},
		),
		RequestDecisionsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "aegis_request_decisions_total",
				Help: "Total number of proxy allow or deny decisions.",
			},
			[]string{"protocol", "action", "policy", "reason"},
		),
		AuditDecisionsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "aegis_audit_decisions_total",
				Help: "Total number of audit-mode would-allow or would-deny decisions.",
			},
			[]string{"protocol", "action", "identity", "fqdn", "policy", "reason"},
		),
		ErrorsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "aegis_errors_total",
				Help: "Total number of proxy errors.",
			},
			[]string{"stage"},
		),
		RequestDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "aegis_request_duration_seconds",
				Help:    "Proxy request duration.",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"method", "protocol"},
		),
		PolicyEvaluationDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "aegis_policy_evaluation_duration_seconds",
				Help:    "Policy evaluation duration.",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"protocol"},
		),
		DNSResolutionsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "aegis_dns_resolutions_total",
				Help: "Total number of DNS resolutions.",
			},
			[]string{"status"},
		),
		DNSDuration: prometheus.NewHistogram(
			prometheus.HistogramOpts{
				Name:    "aegis_dns_resolution_duration_seconds",
				Help:    "DNS resolution duration.",
				Buckets: prometheus.DefBuckets,
			},
		),
		DiscoveryProviderStartsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "aegis_discovery_provider_starts_total",
				Help: "Total number of discovery provider starts.",
			},
			[]string{"provider", "kind"},
		),
		DiscoveryProviderFailuresTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "aegis_discovery_provider_failures_total",
				Help: "Total number of discovery provider failures.",
			},
			[]string{"provider", "kind", "stage"},
		),
		DiscoveryProvidersActive: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "aegis_discovery_providers_active",
				Help: "Number of active discovery providers.",
			},
		),
		IdentityMapEntries: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "aegis_identity_map_entries",
				Help: "Current number of IP to identity mappings per provider.",
			},
			[]string{"provider", "kind"},
		),
		IdentityResolutionsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "aegis_identity_resolutions_total",
				Help: "Total number of identity resolution attempts.",
			},
			[]string{"provider", "kind", "result"},
		),
		IdentityOverlapsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "aegis_identity_overlaps_total",
				Help: "Total number of overlapping identity matches.",
			},
			[]string{"winner_provider", "winner_kind", "shadow_provider", "shadow_kind"},
		),
		ProxyProtocolConnectionsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "aegis_proxy_protocol_connections_total",
				Help: "Total number of proxy protocol connection outcomes.",
			},
			[]string{"result"},
		),
		ConfigReloadsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "aegis_config_reloads_total",
				Help: "Total number of config reload outcomes.",
			},
			[]string{"result"},
		),
		ConnectTunnelsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "aegis_connect_tunnels_total",
				Help: "Total number of CONNECT tunnel outcomes.",
			},
			[]string{"mode", "result"},
		),
		ConnectTunnelsActive: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "aegis_connect_tunnels_active",
				Help: "Current number of active CONNECT tunnels.",
			},
			[]string{"mode"},
		),
		MITMCertificatesTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "aegis_mitm_certificates_total",
				Help: "Total number of MITM certificate cache outcomes.",
			},
			[]string{"result"},
		),
		MITMCACyclesTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "aegis_mitm_ca_cycles_total",
				Help: "Total number of MITM CA lifecycle outcomes.",
			},
			[]string{"result"},
		),
		MITMCertificateCacheEntries: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "aegis_mitm_certificate_cache_entries",
				Help: "Number of certificates currently held in the MITM certificate cache.",
			},
		),
		MITMCertificateCacheEvictions: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "aegis_mitm_certificate_cache_evictions_total",
				Help: "Total number of MITM certificate cache evictions by reason.",
			},
			[]string{"reason"},
		),
		ShutdownsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "aegis_shutdowns_total",
				Help: "Total number of shutdown outcomes.",
			},
			[]string{"result"},
		),
		ShutdownDuration: prometheus.NewHistogram(
			prometheus.HistogramOpts{
				Name:    "aegis_shutdown_duration_seconds",
				Help:    "Shutdown duration.",
				Buckets: prometheus.DefBuckets,
			},
		),
		ShutdownForcedTunnelCloses: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "aegis_shutdown_forced_tunnel_closes_total",
				Help: "Total number of active CONNECT tunnels force-closed during shutdown.",
			},
			[]string{"mode"},
		),
		UpstreamTLSErrorsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "aegis_upstream_tls_errors_total",
				Help: "Total number of upstream TLS errors by stage.",
			},
			[]string{"stage"},
		),
		TLSSNIMissingTotal: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "aegis_tls_sni_missing_total",
				Help: "Total number of TLS connections blocked for missing SNI.",
			},
		),
	}

	reg.MustRegister(
		m.RequestsTotal,
		m.RequestDecisionsTotal,
		m.AuditDecisionsTotal,
		m.ErrorsTotal,
		m.RequestDuration,
		m.PolicyEvaluationDuration,
		m.DNSResolutionsTotal,
		m.DNSDuration,
		m.DiscoveryProviderStartsTotal,
		m.DiscoveryProviderFailuresTotal,
		m.DiscoveryProvidersActive,
		m.IdentityMapEntries,
		m.IdentityResolutionsTotal,
		m.IdentityOverlapsTotal,
		m.ProxyProtocolConnectionsTotal,
		m.ConfigReloadsTotal,
		m.ConnectTunnelsTotal,
		m.ConnectTunnelsActive,
		m.MITMCertificatesTotal,
		m.MITMCACyclesTotal,
		m.MITMCertificateCacheEntries,
		m.MITMCertificateCacheEvictions,
		m.ShutdownsTotal,
		m.ShutdownDuration,
		m.ShutdownForcedTunnelCloses,
		m.UpstreamTLSErrorsTotal,
		m.TLSSNIMissingTotal,
		prometheus.NewGoCollector(),
		prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}),
	)

	return m
}
