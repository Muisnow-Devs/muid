package authngrpc

import (
	"context"
	"errors"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "sanzi.io/muid/api/proto/authn/v1"
	"sanzi.io/muid/internal/authn/ent/userfederatedidentity"
	"sanzi.io/muid/internal/authn/ent/useridentity"
	"sanzi.io/muid/internal/session"
	"sanzi.io/muid/pkg/clientmeta"
	grpcutils "sanzi.io/muid/pkg/grpc_utils"
)

const reauthThreshold = 5 * time.Minute

func (g *GRPCHandler) RevokeFederatedIdentity(
	ctx context.Context,
	req *pb.RevokeFederatedIdentityRequest,
) (*pb.RevokeFederatedIdentityResponse, error) {
	wire := sessionTokenValue(req.GetSessionToken())
	if wire == "" {
		return nil, status.Error(codes.InvalidArgument, "missing session token")
	}

	provider := strings.ToLower(strings.TrimSpace(req.GetProvider()))
	if provider == "" {
		return nil, status.Error(codes.InvalidArgument, "provider is required")
	}

	res, err := g.issuer.ResolveSessionToken(ctx, wire)
	if errors.Is(err, session.ErrSessionNotFound) {
		return nil, status.Error(codes.NotFound, "session not found")
	}
	if errors.Is(err, session.ErrSessionExpired) {
		return nil, status.Error(codes.FailedPrecondition, "session expired")
	}
	if err != nil {
		return nil, grpcutils.GRPCInternalError()
	}
	// Reauth required if the session is too old, to prevent hijacked session from unlinking user account.
	if time.Since(res.IssuedAt) > reauthThreshold {
		return nil, status.Error(codes.FailedPrecondition, "reauthentication required")
	}

	// Soft revoke UserFederatedIdentity & UserIdentity
	now := time.Now()
	_, err = g.db.UserFederatedIdentity.Update().
		Where(
			userfederatedidentity.ProviderEQ(provider),
			userfederatedidentity.RevokedAtIsNil(),
			userfederatedidentity.HasIdentityWith(useridentity.UserIDEQ(res.UserID)),
		).
		SetRevokedAt(now).
		Save(ctx)

	n, err := g.db.UserIdentity.Update().
		Where(
			useridentity.UserID(res.UserID),
			useridentity.Provider(provider),
			useridentity.RevokedAtIsNil(),
		).
		SetRevokedAt(now).
		Save(ctx)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, status.Error(codes.NotFound, "federated identity not found")
	}

	// Publish account unlinked event
	ref, err := g.db.UserRef.Get(ctx, res.UserID)
	if err == nil && ref.Email != "" {
		meta, _ := clientmeta.FromContext(ctx)
		g.notifyAccountUnlinked(ctx, ref.Email, provider, session.SessionMetadata{
			Locale:   meta.Locale,
			Timezone: meta.Timezone,
		})
	}

	out := &pb.RevokeFederatedIdentityResponse{}
	out.SetSuccess(true)
	return out, nil
}

func (g *GRPCHandler) RevokeSession(
	ctx context.Context,
	req *pb.RevokeSessionRequest,
) (*pb.RevokeSessionResponse, error) {
	wire := sessionTokenValue(req.GetSessionToken())
	if wire == "" {
		return nil, status.Error(codes.InvalidArgument, "missing session token")
	}

	err := g.issuer.RevokeSessionToken(ctx, wire)
	if errors.Is(err, session.ErrSessionNotFound) {
		return nil, status.Error(codes.NotFound, "session not found")
	}
	if err != nil {
		return nil, grpcutils.GRPCInternalError()
	}

	out := &pb.RevokeSessionResponse{}
	out.SetSuccess(true)
	return out, nil
}
