package handlers

import (
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestFormatEventTimeUsesLocaleAndTimezone(t *testing.T) {
	t.Parallel()

	ts := timestamppb.New(time.Date(2026, 5, 25, 6, 30, 5, 0, time.UTC))
	got := FormatEventTime(ts, "zh-TW", "Asia/Taipei")

	want := "2026-05-25 14:30:05"
	if got != want {
		t.Fatalf("FormatEventTime() = %q, want %q", got, want)
	}
}
