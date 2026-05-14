package avataringest

import "testing"

func TestValidateAvatarFetchHost(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		host string
		ok   bool
	}{
		{"github.com", true},
		{"avatars.githubusercontent.com", true},
		{"localhost", false},
		{"127.0.0.1", false},
		{"::1", false},
		{"metadata.google.internal", false},
	} {
		tc := tc
		t.Run(tc.host, func(t *testing.T) {
			t.Parallel()
			err := validateAvatarFetchHost(tc.host)
			if tc.ok && err != nil {
				t.Fatalf("expected ok, got %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("expected blocked")
			}
		})
	}
}
