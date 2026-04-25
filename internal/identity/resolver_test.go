package identity

import "testing"

func TestUnknownIdentityHasNoLabels(t *testing.T) {
	id := Unknown()
	if id == nil {
		t.Fatal("Unknown() returned nil")
	}
	if id.Source != "unknown" {
		t.Fatalf("source = %q, want %q", id.Source, "unknown")
	}
	if id.Name != "unknown" {
		t.Fatalf("name = %q, want %q", id.Name, "unknown")
	}
	if id.Labels == nil {
		t.Fatal("labels = nil, want empty map")
	}
	if len(id.Labels) != 0 {
		t.Fatalf("labels = %v, want empty", id.Labels)
	}
}
