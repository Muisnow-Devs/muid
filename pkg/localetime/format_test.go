package localetime

import (
	"testing"
	"time"
)

func TestFormat(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		locale   string
		timezone string
		want     string
	}{
		{
			name:     "english includes numeric timezone offset",
			timezone: "Asia/Taipei",
			want:     "Mon, 25 May 2026 14:30:05 +0800",
		},
		{
			name:     "chinese includes numeric timezone offset",
			timezone: "Asia/Taipei",
			want:     "2026-05-25 14:30:05 +0800",
		},
		{
			name:     "invalid timezone uses UTC",
			timezone: "Not/AZone",
			want:     "Mon, 25 May 2026 06:30:05 +0000",
		},
	}

	instant := time.Date(2026, 5, 25, 6, 30, 5, 0, time.UTC)
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := Format(instant, tt.timezone)
			if got != tt.want {
				t.Fatalf("Format() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestValidTimezone(t *testing.T) {
	t.Parallel()

	if !ValidTimezone("") {
		t.Fatal("expected empty timezone to be valid")
	}
	if !ValidTimezone("Asia/Taipei") {
		t.Fatal("expected Asia/Taipei to be valid")
	}
	if ValidTimezone("Not/AZone") {
		t.Fatal("expected invalid timezone to be rejected")
	}
}
