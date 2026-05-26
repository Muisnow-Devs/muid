package account

import (
	"testing"
	"time"
)

func TestSessionRequiresReauthentication(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name     string
		issuedAt time.Time
		want     bool
	}{
		{
			name:     "within window",
			issuedAt: now.Add(-4 * time.Minute),
			want:     false,
		},
		{
			name:     "exactly five minutes",
			issuedAt: now.Add(-5 * time.Minute),
			want:     false,
		},
		{
			name:     "older than five minutes",
			issuedAt: now.Add(-5*time.Minute - time.Second),
			want:     true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := SessionRequiresReauthentication(tc.issuedAt, now)
			if got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}
