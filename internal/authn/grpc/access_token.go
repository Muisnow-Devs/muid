package authngrpc

import (
	"context"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "sanzi.io/muid/api/proto/authn/v1"
	sessionpb "sanzi.io/muid/api/proto/authn/v1/session"
	"sanzi.io/muid/internal/authn/accesstoken"
	grpcutils "sanzi.io/muid/pkg/grpc_utils"
	"sanzi.io/muid/pkg/log"
)

var errAccessTokenUnavailable = status.Error(
	codes.Unavailable, "session access tokens are not configured")

// IssueAccessToken exchanges a valid session token (resolved by
// AuthnSessionPrincipalInterceptor) for a fresh short-lived JWT access token.
// The access token is never accepted as authentication by authn itself.
func (g *GRPCHandler) IssueAccessToken(
	ctx context.Context,
	_ *pb.IssueAccessTokenRequest,
) (*pb.IssueAccessTokenResponse, error) {
	if g.accessTokens == nil {
		return nil, errAccessTokenUnavailable
	}

	resolved, ok := ResolvedSessionFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "session token required")
	}

	tok, err := g.accessTokens.Mint(ctx, accesstoken.MintInput{
		UserID:        resolved.UserID,
		FallbackEmail: resolved.Email,
	})
	if err != nil {
		log.LogUnexpected(ctx, "issue access token", err.Error(),
			log.UserID(resolved.UserID))
		return nil, grpcutils.GRPCInternalError()
	}

	out := &pb.IssueAccessTokenResponse{}
	out.SetAccessToken(tok)
	return out, nil
}

// attachAccessToken best-effort mints and attaches an access token to sctx.
// Failures are logged and tolerated: login/extension never fail because the
// short-lived token could not be minted.
func (g *GRPCHandler) attachAccessToken(
	ctx context.Context,
	sctx *sessionpb.SessionContext,
	userID uuid.UUID,
	fallbackEmail string,
) {
	if g.accessTokens == nil || sctx == nil {
		return
	}

	tok, err := g.accessTokens.Mint(ctx, accesstoken.MintInput{
		UserID:        userID,
		FallbackEmail: fallbackEmail,
	})
	if err != nil {
		log.LogUnexpected(ctx, "mint session access token", err.Error(),
			log.UserID(userID))
		return
	}
	sctx.SetAccessToken(tok)
}
