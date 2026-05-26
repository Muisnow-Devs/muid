package handlers

import (
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestFormatEventTimeUsesLocaleAndTimezone(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		timezone string
		want     string
	}{
		{
			name:     "english mail timestamp",
			timezone: "Asia/Taipei",
			want:     "Mon, 25 May 2026 14:30:05 +0800",
		},
		{
			name:     "fallback mail timestamp",
			timezone: "Asia/Taipei",
			want:     "Mon, 25 May 2026 14:30:05 +0800",
		},
	}

	ts := timestamppb.New(time.Date(2026, 5, 25, 6, 30, 5, 0, time.UTC))
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := FormatEventTime(ts, tt.timezone)
			if got != tt.want {
				t.Fatalf("FormatEventTime() = %q, want %q", got, tt.want)
			}
		})
	}
}
