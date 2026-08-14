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

// enrichOptionalSessionPrincipal resolves the session like
// enrichSessionPrincipal but tolerates a missing token: anonymous callers
// continue without a resolved session (used by OIDC Authorize, where the
// provider answers LoginRequired instead).
func enrichOptionalSessionPrincipal(iss issuer.SessionIssuer) grpcutils.RequestContextFunc {
	required := enrichSessionPrincipal(iss)
	return func(ctx context.Context, fullMethod string, req any) (context.Context, error) {
		_, ok := grpcutils.WireSessionTokenFromContext(ctx)
		if !ok {
			return ctx, nil
		}
		return required(ctx, fullMethod, req)
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
	required := enrichSessionPrincipal(iss)
	routes := map[string]grpcutils.RequestContextFunc{
		pb.LinkedIdentityService_RevokeLinkedIdentity_FullMethodName: required,
		pb.SessionService_RevokeSession_FullMethodName:               required,
		pb.SessionService_RefreshSession_FullMethodName:              required,
		// The access-token exchange authenticates via the opaque session
		// token only; the JWT it returns is never accepted back by authn.
		pb.SessionService_IssueAccessToken_FullMethodName: required,

		// OIDC provider surface. Authorize is the only optional-session
		// route; token-style RPCs authenticate the client in-message and
		// stay anonymous here.
		pb.OIDCService_Authorize_FullMethodName: enrichOptionalSessionPrincipal(
			iss,
		),
		pb.OIDCService_DecideConsent_FullMethodName:              required,
		pb.OIDCService_GetDeviceAuthorizationInfo_FullMethodName: required,
		pb.OIDCService_DecideDeviceAuthorization_FullMethodName:  required,
		pb.OIDCService_ListGrantedConsents_FullMethodName:        required,
		pb.OIDCService_RevokeConsent_FullMethodName:              required,
	}
	return grpcutils.UnaryRequestContextInterceptor(routes)
}
