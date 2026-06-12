package core

import (
	"strings"
	"testing"

	"sanzi.io/muid/pkg/validation"
)

func TestGenerateUsernameCandidates(t *testing.T) {
	t.Parallel()

	base := randomUsernameBase()
	got := generateUsernameCandidates(base)

	if len(got) != 57 {
		t.Fatalf("len = %d, want 57 (base + 24 suffixes + 32 random)", len(got))
	}
	if got[0] != base {
		t.Errorf("first candidate = %q, want base %q", got[0], base)
	}
	for i := 1; i <= 24; i++ {
		if !strings.HasPrefix(got[i], base+"_") {
			t.Errorf("candidate %d = %q, want prefix %q", i, got[i], base+"_")
		}
	}
	for i, c := range got {
		if !validation.ValidUsername(c) {
			t.Errorf("candidate %d = %q fails ValidUsername", i, c)
		}
	}
}

func TestRandomUsernameBaseShape(t *testing.T) {
	t.Parallel()

	for range 16 {
		base := randomUsernameBase()
		if !strings.HasPrefix(base, "user_") {
			t.Fatalf("base %q missing user_ prefix", base)
		}
		if len(base) != 13 {
			t.Fatalf("base %q length = %d, want 13", base, len(base))
		}
		if !validation.ValidUsername(base) {
			t.Fatalf("base %q fails ValidUsername", base)
		}
	}
}

func TestRandomDisplayNameNonEmpty(t *testing.T) {
	t.Parallel()

	for range 16 {
		if randomDisplayName() == "" {
			t.Fatal("randomDisplayName returned empty string")
		}
	}
}
