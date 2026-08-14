// Package httpmeta bridges untrusted HTTP request attributes onto outgoing gRPC
// metadata for downstream muid services. It extracts the client IP, the
// gateway-verified user id, and resolved geo facts, and attaches them so the
// backends can consume after their workload-principal interceptor verifies the caller.
//
// Trace propagation is handled separately by the grpcutils client dialer via
// log.UnaryClientInterceptor, so it is not duplicated here.
package httpmeta

import (
	"context"
	"net"
	"net/http"
	"strings"

	"google.golang.org/grpc/metadata"
)

const (
	// UserIDKey mirrors internal/authz/grpc.UserIDMetadataKey: the verified
	// caller id the public listener requires. Duplicated as a constant to keep
	// pkg/gateway free of internal/* imports.
	UserIDKey = "x-user-id"
	// ClientIPKey carries the resolved client IP.
	ClientIPKey = "x-client-ip"
	// GeoCountryKey carries the ISO 3166-1 alpha-2 country code when resolved.
	GeoCountryKey = "x-geo-country"
)

// ClientIPConfig controls how the client IP is derived from a request.
type ClientIPConfig struct {
	// TrustForwardHeader, when true, honours proxy-supplied client-IP headers.
	// Only enable behind a trusted proxy (e.g. Cloudflare); otherwise clients
	// can spoof their IP.
	TrustForwardHeader bool
	// RealIPHeader, when set, is a single-value header the trusted proxy
	// populates with the real client IP (e.g. Cloudflare "CF-Connecting-IP").
	// It is preferred over X-Forwarded-For because the proxy overwrites it, so a
	// client cannot spoof it.
	RealIPHeader string
}

// ClientIP returns the best-effort client IP for r. With TrustForwardHeader it
// prefers RealIPHeader (a single trusted value), then the RIGHT-MOST
// X-Forwarded-For entry (the hop attributed by the nearest proxy — the left-most
// entries are client-supplied and spoofable), then X-Real-IP, falling back to
// the transport RemoteAddr.
func ClientIP(r *http.Request, cfg ClientIPConfig) string {
	if cfg.TrustForwardHeader {
		if h := strings.TrimSpace(cfg.RealIPHeader); h != "" {
			if v := strings.TrimSpace(r.Header.Get(h)); v != "" {
				return v
			}
		}
		if ip := rightmostForwarded(r.Header.Get("X-Forwarded-For")); ip != "" {
			return ip
		}
		if xr := strings.TrimSpace(r.Header.Get("X-Real-IP")); xr != "" {
			return xr
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return strings.TrimSpace(r.RemoteAddr)
	}
	return host
}

// rightmostForwarded returns the last non-empty entry of an X-Forwarded-For
// value — the address seen by the nearest trusted proxy. Left-most entries are
// supplied by the client and must not be trusted.
func rightmostForwarded(xff string) string {
	if strings.TrimSpace(xff) == "" {
		return ""
	}
	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		if ip := strings.TrimSpace(parts[i]); ip != "" {
			return ip
		}
	}
	return ""
}

// Fields is the set of attributes to attach as outgoing gRPC metadata. Empty
// values are skipped.
type Fields struct {
	UserID     string
	ClientIP   string
	GeoCountry string
}

// WithOutgoing replaces the gateway-owned outgoing metadata fields. Existing
// values are removed first so an inherited context cannot smuggle duplicate or
// stale identity and client facts to a backend.
func WithOutgoing(ctx context.Context, f Fields) context.Context {
	userID := strings.TrimSpace(f.UserID)
	clientIP := strings.TrimSpace(f.ClientIP)
	geoCountry := strings.TrimSpace(f.GeoCountry)
	md, ok := metadata.FromOutgoingContext(ctx)
	if !ok && userID == "" && clientIP == "" && geoCountry == "" {
		return ctx
	}
	md = md.Copy()
	replace(md, UserIDKey, userID)
	replace(md, ClientIPKey, clientIP)
	replace(md, GeoCountryKey, geoCountry)
	return metadata.NewOutgoingContext(ctx, md)
}

func replace(md metadata.MD, key, value string) {
	md.Delete(key)
	if value != "" {
		md.Set(key, value)
	}
}

// BearerToken extracts the token from an "Authorization: Bearer <token>" value
// (an HTTP header or a gRPC metadata value). It returns "" when the value is
// empty or not a Bearer scheme. Centralised so the gateways don't each re-parse.
func BearerToken(authorization string) string {
	scheme, token, found := strings.Cut(strings.TrimSpace(authorization), " ")
	if !found || !strings.EqualFold(scheme, "bearer") {
		return ""
	}
	return strings.TrimSpace(token)
}
