package validation

import "testing"

func TestValidUsername(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"empty", "", false},
		{"too short ascii", "AbC", false},
		{"too short four chars", "abcd", false},
		{"min len 5", "AbCdE", true},
		{"digits", "user123", true},
		{"underscore", "a_b_c", true},
		{"mixed", "User_01", true},
		{"max len 32", "abcdefghijklmnopqrstuvwxyzabcdef", true},
		{"too long", "abcdefghijklmnopqrstuvwxyzabcdefg", false},
		{"hyphen", "a-b", false},
		{"space", "a b", false},
		{"dot", "a.b", false},
		{"unicode letter", "用户", false},
		{"leading space trimmed invalid", " abc", false},
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
