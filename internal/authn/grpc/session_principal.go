package authngrpc

import (
	"context"
	"errors"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "sanzi.io/muid/api/proto/authn/v1"
	"sanzi.io/muid/internal/identity/issuer"
	"sanzi.io/muid/internal/session"
	grpcutils "sanzi.io/muid/pkg/grpc_utils"
	"sanzi.io/muid/pkg/log"
)

type resolvedSessionKey struct{}

// ResolvedSessionFromContext returns the fully resolved session stored by
// [AuthnSessionPrincipalInterceptor]. ok is false when the route does not use
// session principal enrichment or when no authorization header was present.
func ResolvedSessionFromContext(ctx context.Context) (issuer.ResolvedSession, bool) {
	if ctx == nil {
		return issuer.ResolvedSession{}, false
	}
	s, ok := ctx.Value(resolvedSessionKey{}).(issuer.ResolvedSession)
	return s, ok
}

// enrichSessionPrincipal returns a [grpcutils.RequestContextFunc] that resolves
// the wire token stored by [grpcutils.SessionTokenInterceptor] into a full
// [issuer.ResolvedSession] and attaches it (plus log.UserID) to the context.
//
// Missing token → [codes.Unauthenticated].
// Expired or not-found session → [codes.Unauthenticated].
// Other resolution errors → logged via [log.LogUnexpected] + [codes.Internal].
func enrichSessionPrincipal(iss issuer.SessionIssuer) grpcutils.RequestContextFunc {
	return func(ctx context.Context, _ string, _ any) (context.Context, error) {
		wire, ok := grpcutils.WireSessionTokenFromContext(ctx)
		if !ok {
			return ctx, status.Error(codes.Unauthenticated, "session token required")
		}

		resolved, err := iss.ResolveSessionToken(ctx, wire)
		if errors.Is(err, session.ErrSessionNotFound) || errors.Is(err, session.ErrSessionExpired) {
			return ctx, status.Error(codes.Unauthenticated, "session expired or not found")
		}
		if err != nil {
			log.LogUnexpected(ctx, "enrich session principal", err.Error())
			return ctx, grpcutils.GRPCInternalError()
		}

		ctx = context.WithValue(ctx, resolvedSessionKey{}, resolved)
		ctx = log.WithAttrs(ctx, log.UserID(resolved.UserID))
		return ctx, nil
	}
}

// AuthnSessionPrincipalInterceptor resolves the session token (stored by
// [grpcutils.SessionTokenInterceptor] from the authorization header) for routes
// that require a fully authenticated principal. Resolved session is available via
// [ResolvedSessionFromContext].
//
// Must run after [grpcutils.SessionTokenInterceptor] and
// [AuthnRequestContextInterceptor] in the chain.
func AuthnSessionPrincipalInterceptor(iss issuer.SessionIssuer) grpc.UnaryServerInterceptor {
	return grpcutils.UnaryRequestContextInterceptor(map[string]grpcutils.RequestContextFunc{
		pb.AuthnService_RevokeFederatedIdentity_FullMethodName: enrichSessionPrincipal(iss),
		pb.AuthnService_RevokeSession_FullMethodName:           enrichSessionPrincipal(iss),
		pb.AuthnService_ExtendSession_FullMethodName:           enrichSessionPrincipal(iss),
	})
}
