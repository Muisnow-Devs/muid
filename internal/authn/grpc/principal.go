package authngrpc

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "sanzi.io/muid/api/proto/authn/v1"
	"sanzi.io/muid/internal/session"
	grpcutils "sanzi.io/muid/pkg/grpc_utils"
	"sanzi.io/muid/pkg/log"
)

func (g *GRPCHandler) GetAuthorizedSession(
	ctx context.Context,
	req *pb.GetAuthorizedSessionRequest,
) (*pb.GetAuthorizedSessionResponse, error) {
	wire := sessionTokenValue(req.GetSessionToken())
	if wire == "" {
		return nil, status.Error(codes.InvalidArgument, "missing session token")
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
	out.SetSession(g.issuer.AuthenticatedResultFromResolved(wire, res))
	return out, nil
}

func (g *GRPCHandler) GetAuthenticatedPrincipal(
	ctx context.Context,
	req *pb.GetAuthenticatedPrincipalRequest,
) (*pb.GetAuthenticatedPrincipalResponse, error) {
	wire := sessionTokenValue(req.GetSessionToken())
	if wire == "" {
		return nil, status.Error(codes.InvalidArgument, "missing session token")
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
