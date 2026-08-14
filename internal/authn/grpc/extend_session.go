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

func (g *GRPCHandler) RefreshSession(
	ctx context.Context,
	req *pb.RefreshSessionRequest,
) (*pb.RefreshSessionResponse, error) {
	// Wire token resolved and validated by AuthnSessionPrincipalInterceptor.
	// ResolvedSession is already on ctx; the issuer still needs the raw wire token.
	wire, _ := grpcutils.WireSessionTokenFromContext(ctx)

	sctx, err := g.issuer.RefreshSession(ctx, wire)
	if errors.Is(err, session.ErrSessionNotFound) {
		return nil, status.Error(codes.NotFound, "session not found")
	}
	if errors.Is(err, session.ErrSessionExpired) {
		return nil, status.Error(codes.FailedPrecondition, "session expired")
	}
	if errors.Is(err, session.ErrSessionAbsoluteExpiry) {
		return nil, status.Error(codes.FailedPrecondition, "session absolute expiry reached")
	}
	if err != nil {
		log.LogUnexpected(ctx, "authn extend session", err.Error())
		return nil, grpcutils.GRPCInternalError()
	}

	resolved, _ := ResolvedSessionFromContext(ctx)
	g.attachAccessToken(ctx, sctx, resolved.UserID, resolved.Email)

	out := &pb.RefreshSessionResponse{}
	out.SetSessionContext(sctx)
	return out, nil
}
