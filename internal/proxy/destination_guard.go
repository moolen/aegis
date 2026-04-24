package proxy

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
)

type DestinationGuard struct {
	allowedHostPatterns []string
	allowedCIDRs        []netip.Prefix
	logger              *slog.Logger
}

type destinationBlockedError struct {
	host   string
	ip     net.IP
	reason string
}

func (e *destinationBlockedError) Error() string {
	if e.ip == nil {
		return fmt.Sprintf("destination %q blocked by rebinding protection: %s", e.host, e.reason)
	}
	return fmt.Sprintf("destination %q resolved to blocked address %q: %s", e.host, e.ip.String(), e.reason)
}

func NewDestinationGuard(allowedHostPatterns []string, allowedCIDRs []string, logger *slog.Logger) (*DestinationGuard, error) {
	if logger == nil {
		logger = slog.Default()
	}

	parsedCIDRs := make([]netip.Prefix, 0, len(allowedCIDRs))
	for _, cidr := range allowedCIDRs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil, fmt.Errorf("parse allowed destination cidr %q: %w", cidr, err)
		}
		parsedCIDRs = append(parsedCIDRs, prefix)
	}

	patterns := make([]string, 0, len(allowedHostPatterns))
	for _, pattern := range allowedHostPatterns {
		patterns = append(patterns, strings.ToLower(pattern))
	}

	return &DestinationGuard{
		allowedHostPatterns: patterns,
		allowedCIDRs:        parsedCIDRs,
		logger:              logger,
	}, nil
}

func (g *DestinationGuard) ValidateDirectIP(host string, ip net.IP) error {
	if g == nil || ip == nil {
		return nil
	}
	if g.isAllowedIP(ip) {
		return nil
	}
	if reason, blocked := blockedAddressReason(ip); blocked {
		g.logger.Warn("blocked direct destination address", "host", host, "ip", ip.String(), "reason", reason)
		return &destinationBlockedError{host: host, ip: cloneIP(ip), reason: reason}
	}
	return nil
}

func (g *DestinationGuard) SelectResolvedIP(host string, ips []net.IP) (net.IP, error) {
	if len(ips) == 0 {
		return nil, nil
	}
	if g == nil {
		return cloneIP(ips[0]), nil
	}
	if g.isAllowedHost(host) {
		return cloneIP(ips[0]), nil
	}

	var blocked *destinationBlockedError
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		if g.isAllowedIP(ip) {
			return cloneIP(ip), nil
		}
		if reason, isBlocked := blockedAddressReason(ip); isBlocked && blocked == nil {
			blocked = &destinationBlockedError{host: host, ip: cloneIP(ip), reason: reason}
		}
	}

	if blocked != nil {
		g.logger.Warn("blocked resolved destination address", "host", host, "ip", blocked.ip.String(), "reason", blocked.reason)
		return nil, blocked
	}

	return cloneIP(ips[0]), nil
}

func IsDestinationBlocked(err error) bool {
	var blocked *destinationBlockedError
	return errors.As(err, &blocked)
}

func (g *DestinationGuard) isAllowedHost(host string) bool {
	host = strings.ToLower(host)
	for _, pattern := range g.allowedHostPatterns {
		if matchSimpleGlob(pattern, host) {
			return true
		}
	}
	return false
}

func (g *DestinationGuard) isAllowedIP(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	for _, prefix := range g.allowedCIDRs {
		if prefix.Contains(addr.Unmap()) {
			return true
		}
	}
	return false
}

func blockedAddressReason(ip net.IP) (string, bool) {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return "invalid address", true
	}
	addr = addr.Unmap()

	switch {
	case addr.IsLoopback():
		return "loopback addresses require an explicit allowlist entry", true
	case addr.IsPrivate():
		return "private addresses require an explicit allowlist entry", true
	case addr.IsLinkLocalUnicast():
		return "link-local addresses require an explicit allowlist entry", true
	case addr.IsLinkLocalMulticast():
		return "link-local multicast addresses are not allowed", true
	case addr.IsMulticast():
		return "multicast addresses are not allowed", true
	case addr.IsUnspecified():
		return "unspecified addresses are not allowed", true
	default:
		return "", false
	}
}

func matchSimpleGlob(pattern string, value string) bool {
	patternIndex := 0
	valueIndex := 0
	starIndex := -1
	matchIndex := 0

	for valueIndex < len(value) {
		switch {
		case patternIndex < len(pattern) && pattern[patternIndex] == value[valueIndex]:
			patternIndex++
			valueIndex++
		case patternIndex < len(pattern) && pattern[patternIndex] == '*':
			starIndex = patternIndex
			matchIndex = valueIndex
			patternIndex++
		case starIndex != -1:
			patternIndex = starIndex + 1
			matchIndex++
			valueIndex = matchIndex
		default:
			return false
		}
	}

	for patternIndex < len(pattern) && pattern[patternIndex] == '*' {
		patternIndex++
	}

	return patternIndex == len(pattern)
}

func cloneIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	out := make(net.IP, len(ip))
	copy(out, ip)
	return out
}
