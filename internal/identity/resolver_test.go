package identity

import "testing"

func TestUnknownIdentityHasNoLabels(t *testing.T) {
	id := Unknown()
	if id == nil {
		t.Fatal("Unknown() returned nil")
	}
	if len(id.Labels) != 0 {
		t.Fatalf("labels = %v, want empty", id.Labels)
	}
}
