// Package clientmeta carries client-supplied locale, timezone, and device context for
// RPC/session use via gRPC metadata (not request message fields). Client IP is read from
// x-client-ip only; the gateway must derive it from proxy headers and set that key on
// downstream calls. Event payloads (NATS/pubsub) keep their own fields.
package clientmeta

import (
	"context"
	"errors"
	"strings"

	"google.golang.org/grpc/metadata"

	"sanzi.io/muid/pkg/localetime"
)

const (
	// LocaleMetadataKey is the gRPC metadata key for a BCP-47 locale (e.g. "zh-TW").
	// Empty omits the key; mail defaults to "en".
	LocaleMetadataKey = "x-client-locale"
	// TimezoneMetadataKey is the gRPC metadata key for an IANA time zone (e.g. "Asia/Taipei").
	// Empty omits the key; mail timestamps use UTC.
	TimezoneMetadataKey = "x-client-timezone"
	// DeviceMetadataKey is a human-readable device label for mail (e.g. "Chrome on Windows").
	DeviceMetadataKey = "x-client-device"
	// LocationMetadataKey is a human-readable location for mail (e.g. "Taipei, TW").
	LocationMetadataKey = "x-client-location"
	// UserAgentMetadataKey is the raw User-Agent string when the client sends it explicitly.
	UserAgentMetadataKey = "x-client-user-agent"
	// ClientIPMetadataKey is the client IP set by the gateway after parsing proxy headers
	// (e.g. cf-connecting-ip, x-forwarded-for). Services must not re-parse those headers.
	ClientIPMetadataKey = "x-client-ip"

	maxLocaleLen    = 32
	maxTimezoneLen  = 64
	maxDeviceLen    = 128
	maxLocationLen  = 256
	maxUserAgentLen = 512
	maxClientIPLen  = 45
)

// ErrInvalidTimezone is returned when timezone metadata is non-empty but not a valid IANA name.
var ErrInvalidTimezone = errors.New("timezone must be a valid IANA time zone")

type contextKey struct{}

// ClientMeta holds trimmed client context from gRPC metadata or context.
type ClientMeta struct {
	Locale    string
	Timezone  string
	Device    string
	Location  string
	UserAgent string
	IPAddress string
}

// FromIncomingMetadata reads client metadata from the incoming gRPC call.
func FromIncomingMetadata(ctx context.Context) ClientMeta {
	md, ok := metadata.FromIncomingContext(ctx)
	m := ClientMeta{}
	if !ok {
		return m
	}
	m.Locale = firstMetadataValue(md, LocaleMetadataKey, maxLocaleLen)
	m.Timezone = firstMetadataValue(md, TimezoneMetadataKey, maxTimezoneLen)
	m.Device = firstMetadataValue(md, DeviceMetadataKey, maxDeviceLen)
	m.Location = firstMetadataValue(md, LocationMetadataKey, maxLocationLen)
	m.UserAgent = firstMetadataValue(md, UserAgentMetadataKey, maxUserAgentLen)
	m.IPAddress = firstMetadataValue(md, ClientIPMetadataKey, maxClientIPLen)
	return m.trimmed()
}

// WithContext stores ClientMeta on ctx for handlers after interceptors parse metadata.
func WithContext(ctx context.Context, m ClientMeta) context.Context {
	if ctx == nil {
		return ctx
	}
	return context.WithValue(ctx, contextKey{}, m.trimmed())
}

// FromContext returns ClientMeta attached by [WithContext].
func FromContext(ctx context.Context) (ClientMeta, bool) {
	if ctx == nil {
		return ClientMeta{}, false
	}
	m, ok := ctx.Value(contextKey{}).(ClientMeta)
	return m, ok
}

// EnrichFromIncomingMetadata parses metadata, validates timezone when set, and stores on ctx.
func EnrichFromIncomingMetadata(ctx context.Context) (context.Context, error) {
	m := FromIncomingMetadata(ctx)
	if err := m.validateTimezone(); err != nil {
		return ctx, err
	}
	return WithContext(ctx, m), nil
}

// AppendToOutgoingContext forwards client metadata as outgoing gRPC metadata (not IP).
func AppendToOutgoingContext(ctx context.Context, m ClientMeta) context.Context {
	m = m.trimmed()
	pairs := make([]string, 0, 10)
	if m.Locale != "" {
		pairs = append(pairs, LocaleMetadataKey, m.Locale)
	}
	if m.Timezone != "" {
		pairs = append(pairs, TimezoneMetadataKey, m.Timezone)
	}
	if m.Device != "" {
		pairs = append(pairs, DeviceMetadataKey, m.Device)
	}
	if m.Location != "" {
		pairs = append(pairs, LocationMetadataKey, m.Location)
	}
	if m.UserAgent != "" {
		pairs = append(pairs, UserAgentMetadataKey, m.UserAgent)
	}
	if len(pairs) == 0 {
		return ctx
	}
	return metadata.AppendToOutgoingContext(ctx, pairs...)
}

func (m ClientMeta) trimmed() ClientMeta {
	return ClientMeta{
		Locale:    strings.TrimSpace(m.Locale),
		Timezone:  strings.TrimSpace(m.Timezone),
		Device:    strings.TrimSpace(m.Device),
		Location:  strings.TrimSpace(m.Location),
		UserAgent: strings.TrimSpace(m.UserAgent),
		IPAddress: strings.TrimSpace(m.IPAddress),
	}
}

func (m ClientMeta) validateTimezone() error {
	if !localetime.ValidTimezone(m.Timezone) {
		return ErrInvalidTimezone
	}
	return nil
}

func firstMetadataValue(md metadata.MD, key string, maxLen int) string {
	vals := md.Get(key)
	if len(vals) == 0 {
		return ""
	}
	v := strings.TrimSpace(vals[0])
	if v == "" {
		return ""
	}
	if maxLen > 0 && len(v) > maxLen {
		v = v[:maxLen]
	}
	return v
}
