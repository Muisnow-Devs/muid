package authngrpc

import (
	"context"
	"errors"

	"google.golang.org/protobuf/types/known/timestamppb"

	pb "sanzi.io/muid/api/proto/authn/v1"
	sessionpb "sanzi.io/muid/api/proto/authn/v1/session"
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

// GetSessionPrincipal validates the opaque session token and returns only the
// credential-free principal fields needed by callers. JWT access tokens are
// verified locally by gateways and are never resolvable here.
func (g *GRPCHandler) GetSessionPrincipal(
	ctx context.Context,
	_ *pb.GetSessionPrincipalRequest,
) (*pb.GetSessionPrincipalResponse, error) {
	res, ok, err := g.resolveSessionFromContext(ctx)
	if err != nil {
		return nil, err
	}

	out := &pb.GetSessionPrincipalResponse{}
	if ok {
		principal := &pb.SessionPrincipal{}
		principal.SetUserId(res.UserID.String())
		principal.SetAuthLevel(sessionpb.AuthLevel_AUTH_LEVEL_MEDIUM)
		principal.SetIssuedAt(timestamppb.New(res.IssuedAt.UTC()))
		principal.SetExpiresAt(timestamppb.New(res.ExpiresAt.UTC()))
		out.SetValid(true)
		out.SetPrincipal(principal)
	} else {
		out.SetValid(false)
	}
	return out, nil
}
