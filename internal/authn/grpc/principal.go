package authngrpc

import (
	"context"
	"errors"

	pb "sanzi.io/muid/api/proto/authn/v1"
	"sanzi.io/muid/internal/session"
	grpcutils "sanzi.io/muid/pkg/grpc_utils"
	"sanzi.io/muid/pkg/log"
)

// GetAuthorizedSession validates the session token sent via the authorization
// metadata header ("Session <token>") and returns the resolved session.
// Returns valid=false instead of an error when the session is expired or not
// found — this is the contract used by the gateway to check session validity.
func (g *GRPCHandler) GetAuthorizedSession(
	ctx context.Context,
	req *pb.GetAuthorizedSessionRequest,
) (*pb.GetAuthorizedSessionResponse, error) {
	wire, ok := grpcutils.WireSessionTokenFromContext(ctx)
	if !ok {
		out := &pb.GetAuthorizedSessionResponse{}
		out.SetValid(false)
		return out, nil
	}

	res, err := g.issuer.ResolveSessionToken(ctx, wire)
	if errors.Is(err, session.ErrSessionNotFound) || errors.Is(err, session.ErrSessionExpired) {
		out := &pb.GetAuthorizedSessionResponse{}
		out.SetValid(false)
		return out, nil
	}
	if err != nil {
		log.LogUnexpected(ctx, "authn get session", err.Error())
		return nil, grpcutils.GRPCInternalError()
	}

	out := &pb.GetAuthorizedSessionResponse{}
	out.SetValid(true)
	out.SetSession(g.issuer.AuthenticatedResultFromResolved(res))
	return out, nil
}

// GetAuthenticatedPrincipal resolves the session token sent via the authorization
// metadata header into an authenticated principal for downstream services.
// Returns valid=false instead of an error when the session is expired or not found.
func (g *GRPCHandler) GetAuthenticatedPrincipal(
	ctx context.Context,
	req *pb.GetAuthenticatedPrincipalRequest,
) (*pb.GetAuthenticatedPrincipalResponse, error) {
	wire, ok := grpcutils.WireSessionTokenFromContext(ctx)
	if !ok {
		out := &pb.GetAuthenticatedPrincipalResponse{}
		out.SetValid(false)
		return out, nil
	}

	res, err := g.issuer.ResolveSessionToken(ctx, wire)
	if errors.Is(err, session.ErrSessionNotFound) || errors.Is(err, session.ErrSessionExpired) {
		out := &pb.GetAuthenticatedPrincipalResponse{}
		out.SetValid(false)
		return out, nil
	}
	if err != nil {
		log.LogUnexpected(ctx, "authn get principal", err.Error())
		return nil, grpcutils.GRPCInternalError()
	}

	out := &pb.GetAuthenticatedPrincipalResponse{}
	out.SetValid(true)
	out.SetPrincipal(g.issuer.AuthenticatedPrincipalFromResolved(res))
	return out, nil
}
