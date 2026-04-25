package dns

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/moolen/aegis/internal/metrics"
)

type Config struct {
	CacheTTL time.Duration
	Timeout  time.Duration
	Servers  []string
}

type LookupFunc func(context.Context, string) ([]net.IP, error)

type Resolver struct {
	cacheTTL time.Duration
	timeout  time.Duration
	lookupFn LookupFunc
	logger   *slog.Logger
	metrics  *metrics.Metrics

	mu    sync.Mutex
	cache map[string]cacheEntry
}

type cacheEntry struct {
	ips     []net.IP
	expires time.Time
}

func NewResolver(cfg Config, lookupFn LookupFunc, logger *slog.Logger, m *metrics.Metrics) *Resolver {
	if logger == nil {
		logger = slog.Default()
	}
	if lookupFn == nil {
		lookupFn = NewSystemLookupFunc(cfg)
	}

	return &Resolver{
		cacheTTL: cfg.CacheTTL,
		timeout:  cfg.Timeout,
		lookupFn: lookupFn,
		logger:   logger,
		metrics:  m,
		cache:    make(map[string]cacheEntry),
	}
}

func (r *Resolver) LookupNetIP(ctx context.Context, host string) ([]net.IP, error) {
	if ips, ok := r.lookupCache(host); ok {
		return ips, nil
	}

	if r.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, r.timeout)
		defer cancel()
	}

	start := time.Now()
	ips, err := r.lookupFn(ctx, host)
	duration := time.Since(start)

	if r.metrics != nil {
		r.metrics.DNSDuration.Observe(duration.Seconds())
	}

	if err != nil {
		if r.metrics != nil {
			r.metrics.DNSResolutionsTotal.WithLabelValues("error").Inc()
		}
		r.logger.Error("dns lookup failed", "host", host, "duration", duration, "error", err)
		return nil, fmt.Errorf("lookup host %q: %w", host, err)
	}

	if r.metrics != nil {
		r.metrics.DNSResolutionsTotal.WithLabelValues("success").Inc()
	}

	r.storeCache(host, ips)
	r.logger.Info("dns lookup succeeded", "host", host, "ips", ipStrings(ips), "duration", duration)

	return cloneIPs(ips), nil
}

func NewSystemLookupFunc(cfg Config) LookupFunc {
	resolver := &net.Resolver{}
	if len(cfg.Servers) > 0 {
		resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				server := cfg.Servers[0]
				dialer := &net.Dialer{}
				return dialer.DialContext(ctx, network, server)
			},
		}
	}

	return func(ctx context.Context, host string) ([]net.IP, error) {
		addrs, err := resolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}

		ips := make([]net.IP, 0, len(addrs))
		for _, addr := range addrs {
			ips = append(ips, net.IP(addr.AsSlice()))
		}

		return ips, nil
	}
}

func (r *Resolver) lookupCache(host string) ([]net.IP, bool) {
	if r.cacheTTL <= 0 {
		return nil, false
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	entry, ok := r.cache[host]
	if !ok || time.Now().After(entry.expires) {
		if ok {
			delete(r.cache, host)
		}
		return nil, false
	}

	return cloneIPs(entry.ips), true
}

func (r *Resolver) storeCache(host string, ips []net.IP) {
	if r.cacheTTL <= 0 {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.cache[host] = cacheEntry{
		ips:     cloneIPs(ips),
		expires: time.Now().Add(r.cacheTTL),
	}
}

func cloneIPs(ips []net.IP) []net.IP {
	cloned := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		copied := make(net.IP, len(ip))
		copy(copied, ip)
		cloned = append(cloned, copied)
	}
	return cloned
}

func ipStrings(ips []net.IP) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}
