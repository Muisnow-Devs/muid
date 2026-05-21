package utils

import "testing"

func TestFirstNonEmpty(t *testing.T) {
	t.Parallel()

	got := FirstNonEmpty(" ", "\t", " first ", "second")
	if got != "first" {
		t.Fatalf("FirstNonEmpty() = %q, want first", got)
	}
}

func TestFirstNonEmptyAllBlank(t *testing.T) {
	t.Parallel()

	got := FirstNonEmpty("", "  ")
	if got != "" {
		t.Fatalf("FirstNonEmpty() = %q, want empty", got)
	}
}

func TestTrimNonEmpty(t *testing.T) {
	t.Parallel()

	got := TrimNonEmpty([]string{" openid ", "", " profile", "\t", "email "})
	want := []string{"openid", "profile", "email"}
	if len(got) != len(want) {
		t.Fatalf("len(got) = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
