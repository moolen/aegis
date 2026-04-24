package metrics

import "github.com/prometheus/client_golang/prometheus"

type Metrics struct {
	RequestsTotal                  *prometheus.CounterVec
	ErrorsTotal                    *prometheus.CounterVec
	RequestDuration                *prometheus.HistogramVec
	DNSResolutionsTotal            *prometheus.CounterVec
	DNSDuration                    prometheus.Histogram
	DiscoveryProviderStartsTotal   *prometheus.CounterVec
	DiscoveryProviderFailuresTotal *prometheus.CounterVec
	DiscoveryProvidersActive       prometheus.Gauge
	IdentityResolutionsTotal       *prometheus.CounterVec
	IdentityOverlapsTotal          *prometheus.CounterVec
	ProxyProtocolConnectionsTotal  *prometheus.CounterVec
	ConfigReloadsTotal             *prometheus.CounterVec
	ConnectTunnelsTotal            *prometheus.CounterVec
	MITMCertificatesTotal          *prometheus.CounterVec
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
		MITMCertificatesTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "aegis_mitm_certificates_total",
				Help: "Total number of MITM certificate cache outcomes.",
			},
			[]string{"result"},
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
		m.ErrorsTotal,
		m.RequestDuration,
		m.DNSResolutionsTotal,
		m.DNSDuration,
		m.DiscoveryProviderStartsTotal,
		m.DiscoveryProviderFailuresTotal,
		m.DiscoveryProvidersActive,
		m.IdentityResolutionsTotal,
		m.IdentityOverlapsTotal,
		m.ProxyProtocolConnectionsTotal,
		m.ConfigReloadsTotal,
		m.ConnectTunnelsTotal,
		m.MITMCertificatesTotal,
		m.TLSSNIMissingTotal,
		prometheus.NewGoCollector(),
		prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}),
	)

	return m
}
