package grpcutils

import (
	"context"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"sanzi.io/muid/internal/session"
)

const (
	// AuthorizationMetadataKey is the gRPC metadata key for the HTTP Authorization header.
	AuthorizationMetadataKey = "authorization"

	sessionScheme = "session"
)

type sessionTokenCtxKey struct{}

// SessionTokenInterceptor reads the gRPC "authorization" metadata header and expects
// the scheme "Session <wire-token>" (case-insensitive scheme).
//
// - No header present: pass-through (token is optional; call sites enforce presence).
// - Header present but scheme is not "Session": [codes.Unauthenticated].
// - Header present, correct scheme, but malformed wire token: [codes.Unauthenticated].
// - Header present and valid: raw wire token stored on ctx for downstream use.
//
// Actual session resolution (DB/cache lookup) is NOT performed here; use
// [WireSessionTokenFromContext] downstream to retrieve the token.
func SessionTokenInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return handler(ctx, req)
		}

		vals := md.Get(AuthorizationMetadataKey)
		if len(vals) == 0 || strings.TrimSpace(vals[0]) == "" {
			return handler(ctx, req)
		}

		raw := strings.TrimSpace(vals[0])
		scheme, token, found := strings.Cut(raw, " ")
		if !found || strings.ToLower(strings.TrimSpace(scheme)) != sessionScheme {
			return nil, status.Error(codes.Unauthenticated, "invalid authorization scheme")
		}

		wire := strings.TrimSpace(token)
		if _, _, err := session.ParseWireSessionToken(wire); err != nil {
			return nil, status.Error(codes.Unauthenticated, "invalid session token")
		}

		return handler(context.WithValue(ctx, sessionTokenCtxKey{}, wire), req)
	}
}

// WireSessionTokenFromContext returns the raw wire token stored by [SessionTokenInterceptor].
func WireSessionTokenFromContext(ctx context.Context) (string, bool) {
	if ctx == nil {
		return "", false
	}
	wire, ok := ctx.Value(sessionTokenCtxKey{}).(string)
	return wire, ok && wire != ""
}
