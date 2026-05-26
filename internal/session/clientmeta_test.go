package session

import (
	"testing"

	"sanzi.io/muid/pkg/clientmeta"
)

func TestMergeMailClientContext_prefersPrimary(t *testing.T) {
	t.Parallel()

	primary := MailClientContext{
		Device:    "Chrome",
		Location:  "TW",
		IPAddress: "203.0.113.1",
	}
	fallback := MailClientContext{
		Device:    "stale",
		Location:  "stale",
		IPAddress: "stale",
		Locale:    "en",
	}

	got := MergeMailClientContext(primary, fallback)
	if got.Device != "Chrome" || got.Location != "TW" || got.IPAddress != "203.0.113.1" {
		t.Fatalf("got %+v", got)
	}
	if got.Locale != "en" {
		t.Fatalf("locale: %q", got.Locale)
	}
}

func TestApplyClientMeta_roundTripsThroughMailClientContext(t *testing.T) {
	t.Parallel()

	store := EmailOTPStore(StepStart, &EmailOTPFlow{Email: "a@b.c"})
	ApplyClientMeta(&store, clientmeta.ClientMeta{
		Locale:    "zh-TW",
		Timezone:  "Asia/Taipei",
		Device:    "Firefox",
		Location:  "Taipei",
		UserAgent: "Mozilla/5.0",
		IPAddress: "127.0.0.1",
	})

	got := store.MailClientContext()
	if got.Device != "Firefox" || got.IPAddress != "127.0.0.1" {
		t.Fatalf("got %+v", got)
	}
}
