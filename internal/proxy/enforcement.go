package proxy

import (
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/moolen/aegis/internal/config"
)

type EnforcementOverrideController struct {
	logger *slog.Logger

	mu       sync.RWMutex
	override string
}

func NewEnforcementOverrideController(logger *slog.Logger) *EnforcementOverrideController {
	if logger == nil {
		logger = slog.Default()
	}
	return &EnforcementOverrideController{logger: logger}
}

func (c *EnforcementOverrideController) OverrideMode() (string, bool) {
	if c == nil {
		return "", false
	}

	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.override == "" {
		return "", false
	}
	return c.override, true
}

func (c *EnforcementOverrideController) SetOverride(mode string) error {
	if c == nil {
		return fmt.Errorf("enforcement override controller is not configured")
	}

	normalized := config.NormalizeEnforcementMode(mode)
	switch normalized {
	case config.EnforcementAudit, config.EnforcementEnforce:
	default:
		return fmt.Errorf("invalid enforcement mode %q", mode)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.override == normalized {
		return nil
	}
	c.override = normalized
	c.logger.Warn("global enforcement override updated", "override_mode", normalized)
	return nil
}

func (c *EnforcementOverrideController) ClearOverride() {
	if c == nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.override == "" {
		return
	}
	c.override = ""
	c.logger.Warn("global enforcement override cleared")
}

func EffectiveEnforcementMode(configured string, override *EnforcementOverrideController) string {
	if overrideMode, ok := override.OverrideMode(); ok {
		return overrideMode
	}
	return normalizeConfiguredEnforcementMode(configured)
}

func IsAuditMode(configured string, override *EnforcementOverrideController) bool {
	return EffectiveEnforcementMode(configured, override) == config.EnforcementAudit
}

func normalizeConfiguredEnforcementMode(mode string) string {
	normalized := config.NormalizeEnforcementMode(strings.TrimSpace(mode))
	if normalized == "" {
		return config.EnforcementEnforce
	}
	return normalized
}
