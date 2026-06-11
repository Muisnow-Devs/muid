package authngrpc

import (
	"context"
	"errors"

	pb "sanzi.io/muid/api/proto/authn/v1"
	"sanzi.io/muid/internal/identity/issuer"
	"sanzi.io/muid/internal/session"
	grpcutils "sanzi.io/muid/pkg/grpc_utils"
	"sanzi.io/muid/pkg/log"
)

func (g *GRPCHandler) resolveSessionFromContext(
	ctx context.Context,
) (issuer.ResolvedSession, bool, error) {
	wire, ok := grpcutils.WireSessionTokenFromContext(ctx)
	if !ok {
		return issuer.ResolvedSession{}, false, nil
	}

	resolved, err := g.issuer.ResolveSessionToken(ctx, wire)
	if errors.Is(err, session.ErrSessionNotFound) || errors.Is(err, session.ErrSessionExpired) {
		return issuer.ResolvedSession{}, false, nil
	}
	if err != nil {
		log.LogUnexpected(ctx, "resolve authn session", err.Error())
		return issuer.ResolvedSession{}, false, grpcutils.GRPCInternalError()
	}
	return resolved, true, nil
}

// GetAuthorizedSession validates the opaque session token sent via the
// authorization metadata header ("Session <token>") and returns the resolved
// session. JWT access tokens are never resolvable here — callers verify those
// locally via the JWKS served by GetPublicKeys.
// Returns valid=false instead of an error when the session is expired or not
// found — this is the contract used by the gateway to check session validity.
func (g *GRPCHandler) GetAuthorizedSession(
	ctx context.Context,
	req *pb.GetAuthorizedSessionRequest,
) (*pb.GetAuthorizedSessionResponse, error) {
	res, ok, err := g.resolveSessionFromContext(ctx)
	if err != nil {
		return nil, err
	}

	out := &pb.GetAuthorizedSessionResponse{}
	if ok {
		out.SetValid(true)
		out.SetSession(g.issuer.AuthenticatedResultFromResolved(res))
	} else {
		out.SetValid(false)
	}
	return out, nil
}

// GetAuthenticatedPrincipal resolves the opaque session token sent via the
// authorization metadata header into an authenticated principal for downstream
// services. JWT access tokens are not accepted.
// Returns valid=false instead of an error when the session is expired or not found.
func (g *GRPCHandler) GetAuthenticatedPrincipal(
	ctx context.Context,
	req *pb.GetAuthenticatedPrincipalRequest,
) (*pb.GetAuthenticatedPrincipalResponse, error) {
	res, ok, err := g.resolveSessionFromContext(ctx)
	if err != nil {
		return nil, err
	}

	out := &pb.GetAuthenticatedPrincipalResponse{}
	if ok {
		out.SetValid(true)
		out.SetPrincipal(g.issuer.AuthenticatedPrincipalFromResolved(res))
	} else {
		out.SetValid(false)
	}
	return out, nil
}
