package localetime

import (
	"testing"
	"time"
)

func TestFormatEnglishLocalTime(t *testing.T) {
	t.Parallel()

	instant := time.Date(2026, 5, 25, 6, 30, 5, 0, time.UTC)
	got := Format(instant, "en", "Asia/Taipei")

	want := "Mon, 25 May 2026 14:30:05 CST"
	if got != want {
		t.Fatalf("Format() = %q, want %q", got, want)
	}
}

func TestFormatChineseLocalTime(t *testing.T) {
	t.Parallel()

	instant := time.Date(2026, 5, 25, 6, 30, 5, 0, time.UTC)
	got := Format(instant, "zh-TW", "Asia/Taipei")

	want := "2026-05-25 14:30:05"
	if got != want {
		t.Fatalf("Format() = %q, want %q", got, want)
	}
}

func TestFormatInvalidTimezoneUsesUTC(t *testing.T) {
	t.Parallel()

	instant := time.Date(2026, 5, 25, 6, 30, 5, 0, time.UTC)
	got := Format(instant, "en", "Not/AZone")

	want := "Mon, 25 May 2026 06:30:05 UTC"
	if got != want {
		t.Fatalf("Format() = %q, want %q", got, want)
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
