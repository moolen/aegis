package metrics

import "github.com/prometheus/client_golang/prometheus"

type Metrics struct {
	RequestsTotal       *prometheus.CounterVec
	ErrorsTotal         *prometheus.CounterVec
	RequestDuration     *prometheus.HistogramVec
	DNSResolutionsTotal *prometheus.CounterVec
	DNSDuration         prometheus.Histogram
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
	}

	reg.MustRegister(
		m.RequestsTotal,
		m.ErrorsTotal,
		m.RequestDuration,
		m.DNSResolutionsTotal,
		m.DNSDuration,
		prometheus.NewGoCollector(),
		prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}),
	)

	return m
}
