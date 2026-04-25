package proxy

import (
	"io"
	"log/slog"
	"testing"
)

func TestEffectiveEnforcementModeUsesConfiguredModeWithoutOverride(t *testing.T) {
	controller := NewEnforcementOverrideController(slog.New(slog.NewTextHandler(io.Discard, nil)))

	if got := EffectiveEnforcementMode("audit", controller); got != "audit" {
		t.Fatalf("EffectiveEnforcementMode() = %q, want %q", got, "audit")
	}
	if !IsAuditMode("audit", controller) {
		t.Fatal("IsAuditMode() = false, want true")
	}
}

func TestEffectiveEnforcementModeUsesOverrideWhenSet(t *testing.T) {
	controller := NewEnforcementOverrideController(slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := controller.SetOverride("audit"); err != nil {
		t.Fatalf("SetOverride() error = %v", err)
	}

	if got := EffectiveEnforcementMode("enforce", controller); got != "audit" {
		t.Fatalf("EffectiveEnforcementMode() = %q, want %q", got, "audit")
	}

	controller.ClearOverride()
	if got := EffectiveEnforcementMode("enforce", controller); got != "enforce" {
		t.Fatalf("EffectiveEnforcementMode() after clear = %q, want %q", got, "enforce")
	}
}

func TestSetOverrideRejectsInvalidMode(t *testing.T) {
	controller := NewEnforcementOverrideController(slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := controller.SetOverride("block"); err == nil {
		t.Fatal("expected SetOverride() to fail")
	}
}
