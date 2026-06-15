package app

import (
	"context"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"sanzi.io/muid/pkg/gateway/httpmeta"
	"sanzi.io/muid/pkg/gateway/jwtauth"
	"sanzi.io/muid/pkg/gateway/ratelimit"
	"sanzi.io/muid/pkg/log"
)

// authInterceptor verifies a Bearer session access token from request metadata
// and attaches the claims to the context. The curated BFF surface has no public
// methods, so a missing or invalid token is rejected with Unauthenticated
// (fail-closed) rather than passed through as anonymous.
func authInterceptor(verifier *jwtauth.Verifier) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		token := bearerFromMetadata(ctx)
		if token == "" {
			return nil, status.Error(codes.Unauthenticated, "authentication required")
		}
		claims, err := verifier.Verify(ctx, token)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, "invalid session token")
		}
		return handler(jwtauth.WithClaims(ctx, claims), req)
	}
}

// rateLimitInterceptor enforces a fixed-window quota keyed by the authenticated
// user, falling back to the caller's IP for anonymous requests.
func rateLimitInterceptor(limiter *ratelimit.Limiter, trustForwardHeader bool) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		identifier := callerIdentifier(ctx, trustForwardHeader)
		res, err := limiter.Allow(ctx, identifier)
		if err != nil {
			log.LogUnexpected(ctx, "gateway-services rate limit", err.Error())
			return nil, status.Error(codes.Unavailable, "rate limiter unavailable")
		}
		if !res.Allowed {
			return nil, status.Error(codes.ResourceExhausted, "rate limit exceeded")
		}
		return handler(ctx, req)
	}
}

// callerIdentifier returns "user:<id>" for authenticated callers, otherwise the
// client IP (from the trusted edge's x-client-ip metadata or the gRPC peer).
func callerIdentifier(ctx context.Context, trustForwardHeader bool) string {
	if claims, ok := jwtauth.ClaimsFromContext(ctx); ok {
		return "user:" + claims.UserID.String()
	}
	if trustForwardHeader {
		if md, ok := metadata.FromIncomingContext(ctx); ok {
			if v := md.Get(httpmeta.ClientIPKey); len(v) > 0 && strings.TrimSpace(v[0]) != "" {
				return "ip:" + strings.TrimSpace(v[0])
			}
		}
	}
	if p, ok := peer.FromContext(ctx); ok && p.Addr != nil {
		host := p.Addr.String()
		if h, _, found := strings.Cut(host, ":"); found {
			host = h
		}
		return "ip:" + host
	}
	return "ip:unknown"
}

func bearerFromMetadata(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	vals := md.Get("authorization")
	if len(vals) == 0 {
		return ""
	}
	scheme, token, found := strings.Cut(strings.TrimSpace(vals[0]), " ")
	if !found || !strings.EqualFold(scheme, "bearer") {
		return ""
	}
	return strings.TrimSpace(token)
}

// newRateLimiter builds the services gateway's limiter from config.
func newRateLimiter(deps *InfraDependencies) *ratelimit.Limiter {
	cfg := deps.GlobalConfig
	return ratelimit.New(deps.Redis, ratelimit.Config{
		Limit:  cfg.RateLimit,
		Window: time.Duration(cfg.RateLimitWindowSeconds) * time.Second,
		Prefix: "services",
	})
}
