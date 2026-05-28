package authngrpc

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "sanzi.io/muid/api/proto/authn/v1"
	grpcutils "sanzi.io/muid/pkg/grpc_utils"
	"sanzi.io/muid/pkg/log"

	"sanzi.io/muid/internal/session"
)

func (g *GRPCHandler) ExtendSession(
	ctx context.Context,
	req *pb.ExtendSessionRequest,
) (*pb.ExtendSessionResponse, error) {
	wire, err := requiredWireSession(ctx)
	if err != nil {
		return nil, err
	}

	sctx, err := g.issuer.ExtendSession(ctx, wire)
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

	out := &pb.ExtendSessionResponse{}
	out.SetSessionContext(sctx)
	return out, nil
}
