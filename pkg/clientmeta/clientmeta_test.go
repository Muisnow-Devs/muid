package clientmeta

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc/metadata"
)

func TestFromIncomingMetadata_andContext(t *testing.T) {
	t.Parallel()

	ctx := metadata.NewIncomingContext(
		context.Background(),
		metadata.Pairs(
			LocaleMetadataKey, "  zh-TW  ",
			TimezoneMetadataKey, "Asia/Taipei",
			DeviceMetadataKey, "Chrome",
			LocationMetadataKey, "Taipei",
			UserAgentMetadataKey, "Mozilla/5.0",
			ClientIPMetadataKey, "203.0.113.5",
		),
	)

	got := FromIncomingMetadata(ctx)
	if got.Locale != "zh-TW" || got.Timezone != "Asia/Taipei" {
		t.Fatalf("locale/timezone: %+v", got)
	}
	if got.Device != "Chrome" || got.Location != "Taipei" {
		t.Fatalf("device/location: %+v", got)
	}
	if got.UserAgent != "Mozilla/5.0" || got.IPAddress != "203.0.113.5" {
		t.Fatalf("ua/ip: %+v", got)
	}

	ctx, err := EnrichFromIncomingMetadata(ctx)
	if err != nil {
		t.Fatalf("enrich: %v", err)
	}
	stored, ok := FromContext(ctx)
	if !ok {
		t.Fatal("missing on context")
	}
	if stored.IPAddress != "203.0.113.5" {
		t.Fatalf("context ip: %q", stored.IPAddress)
	}
}

func TestFromIncomingMetadata_ignoresProxyHeaders(t *testing.T) {
	t.Parallel()

	ctx := metadata.NewIncomingContext(
		context.Background(),
		metadata.Pairs(
			"x-forwarded-for", "198.51.100.2",
			"cf-connecting-ip", "203.0.113.1",
		),
	)
	got := FromIncomingMetadata(ctx)
	if got.IPAddress != "" {
		t.Fatalf("ip should be empty without x-client-ip: %q", got.IPAddress)
	}
}

func TestEnrichFromIncomingMetadata_invalidTimezone(t *testing.T) {
	t.Parallel()

	ctx := metadata.NewIncomingContext(
		context.Background(),
		metadata.Pairs(TimezoneMetadataKey, "Not/A/Zone"),
	)
	_, err := EnrichFromIncomingMetadata(ctx)
	if !errors.Is(err, ErrInvalidTimezone) {
		t.Fatalf("err: %v", err)
	}
}

func TestAppendToOutgoingContext(t *testing.T) {
	t.Parallel()

	ctx := AppendToOutgoingContext(context.Background(), ClientMeta{
		Locale:    "en",
		Timezone:  "UTC",
		Device:    "Safari",
		Location:  "TW",
		UserAgent: "UA",
		IPAddress: "1.2.3.4",
	})
	md, ok := metadata.FromOutgoingContext(ctx)
	if !ok {
		t.Fatal("missing outgoing metadata")
	}
	if md.Get(LocaleMetadataKey)[0] != "en" {
		t.Fatalf("locale: %v", md.Get(LocaleMetadataKey))
	}
	if md.Get(TimezoneMetadataKey)[0] != "UTC" {
		t.Fatalf("timezone: %v", md.Get(TimezoneMetadataKey))
	}
	if md.Get(DeviceMetadataKey)[0] != "Safari" {
		t.Fatalf("device: %v", md.Get(DeviceMetadataKey))
	}
	if len(md.Get(ClientIPMetadataKey)) != 0 {
		t.Fatal("ip must not be appended to outgoing metadata")
	}
}
