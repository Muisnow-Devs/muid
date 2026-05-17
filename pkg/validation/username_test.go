package validation

import (
	"errors"
	"testing"
)

func TestValidUsername(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"empty", "", false},
		{"too short four chars", "abcd", false},
		{"min len 5", "abcde", true},
		{"digits", "user123", true},
		{"underscore interior", "a_b_c", true},
		{"period interior", "a.b.c", true},
		{"max len 16", "abcdefghijklmnop", true},
		{"too long", "abcdefghijklmnopq", false},
		{"starts underscore", "_abcde", false},
		{"starts period", ".abcde", false},
		{"uppercase", "AbCdE", false},
		{"mixed case", "User_01", false},
		{"hyphen", "a-b-c", false},
		{"space", "a b c", false},
		{"unicode letter", "用户abcde", false},
		{"leading space", " abcde", false},
		{"only underscore chars after first", "a____", true},
		{"ends period", "abcde.", true},
		{"ends underscore", "abcde_", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := ValidUsername(tc.in); got != tc.want {
				t.Fatalf("ValidUsername(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestCheckUsername(t *testing.T) {
	t.Parallel()
	if err := CheckUsername("valid1"); err != nil {
		t.Fatalf("CheckUsername(valid) = %v, want nil", err)
	}
	if err := CheckUsername("INVALID"); !errors.Is(err, ErrInvalidUsername) {
		t.Fatalf("CheckUsername(invalid) = %v, want ErrInvalidUsername", err)
	}
}
