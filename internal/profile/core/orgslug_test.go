package core

import (
	"strings"
	"testing"

	"sanzi.io/muid/pkg/validation"
)

func TestSlugifyDisplayName(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"simple", "Acme Corp", "acme-corp"},
		{"punctuation collapsed", "Hello,  World!!!", "hello-world"},
		{"edges trimmed", "  --Acme--  ", "acme"},
		{"already slug", "acme-corp", "acme-corp"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := slugifyDisplayName(tc.in); got != tc.want {
				t.Fatalf("slugifyDisplayName(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestSlugifyDisplayNameFallsBackToRandom(t *testing.T) {
	t.Parallel()
	// Nothing alphanumeric, or too short, yields a random valid base.
	for _, in := range []string{"", "  ", "!!", "x", "片"} {
		got := slugifyDisplayName(in)
		if !validation.ValidOrgSlug(got) {
			t.Errorf("slugifyDisplayName(%q) = %q is not a valid slug", in, got)
		}
		if !strings.HasPrefix(got, "org-") {
			t.Errorf("slugifyDisplayName(%q) = %q, want random org- base", in, got)
		}
	}
}

func TestGenerateSlugCandidates(t *testing.T) {
	t.Parallel()

	base := "acme"
	got := generateSlugCandidates(base)

	if len(got) != 57 {
		t.Fatalf("len = %d, want 57 (base + 24 suffixes + 32 random)", len(got))
	}
	if got[0] != base {
		t.Errorf("first candidate = %q, want base %q", got[0], base)
	}
	if got[1] != "acme-2" {
		t.Errorf("second candidate = %q, want acme-2", got[1])
	}
	for i, c := range got {
		if !validation.ValidOrgSlug(c) {
			t.Errorf("candidate %d = %q fails ValidOrgSlug", i, c)
		}
	}
}
