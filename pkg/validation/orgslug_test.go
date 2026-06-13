package validation

import (
	"errors"
	"strings"
	"testing"
)

func TestValidOrgSlug(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"empty", "", false},
		{"too short two chars", "ab", false},
		{"min len 3", "abc", true},
		{"digits", "acme123", true},
		{"interior hyphen", "acme-corp", true},
		{"multiple interior hyphens", "a-b-c-d", true},
		{"max len 63", strings.Repeat("a", 63), true},
		{"too long 64", strings.Repeat("a", 64), false},
		{"leading hyphen", "-acme", false},
		{"trailing hyphen", "acme-", false},
		{"uppercase", "Acme", false},
		{"underscore", "acme_corp", false},
		{"period", "acme.corp", false},
		{"space", "acme corp", false},
		{"unicode", "acmé-corp", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := ValidOrgSlug(tc.in); got != tc.want {
				t.Fatalf("ValidOrgSlug(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestCheckOrgSlug(t *testing.T) {
	t.Parallel()
	if err := CheckOrgSlug("acme-corp"); err != nil {
		t.Fatalf("CheckOrgSlug(valid) = %v, want nil", err)
	}
	if err := CheckOrgSlug("Acme"); !errors.Is(err, ErrInvalidOrgSlug) {
		t.Fatalf("CheckOrgSlug(invalid) = %v, want ErrInvalidOrgSlug", err)
	}
}
