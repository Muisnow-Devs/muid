package authngrpc

import (
	"context"
	"errors"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "sanzi.io/muid/api/proto/authn/v1"
	"sanzi.io/muid/internal/authn/authnaudit"
	"sanzi.io/muid/internal/authn/ent"
	"sanzi.io/muid/internal/authn/ent/userfederatedidentity"
	"sanzi.io/muid/internal/authn/ent/useridentity"
	"sanzi.io/muid/internal/session"
	"sanzi.io/muid/pkg/audit"
	"sanzi.io/muid/pkg/clientmeta"
	"sanzi.io/muid/pkg/enttx"
	grpcutils "sanzi.io/muid/pkg/grpc_utils"
)

const reauthThreshold = 5 * time.Minute

func (g *GRPCHandler) RevokeLinkedIdentity(
	ctx context.Context,
	req *pb.RevokeLinkedIdentityRequest,
) (*pb.RevokeLinkedIdentityResponse, error) {
	// Session resolved and validated by AuthnSessionPrincipalInterceptor.
	resolved, _ := ResolvedSessionFromContext(ctx)

	provider := strings.ToLower(strings.TrimSpace(req.GetProvider()))
	if provider == "" {
		return nil, status.Error(codes.InvalidArgument, "provider is required")
	}
	// Require fresh authentication to prevent hijacked sessions from unlinking accounts.
	if time.Since(resolved.IssuedAt) > reauthThreshold {
		return nil, status.Error(codes.FailedPrecondition, "reauthentication required")
	}

	now := time.Now()
	revokedCount, err := enttx.Run(ctx, g.db.Tx,
		func(ctx context.Context, tx *ent.Tx) (int, error) {
			federatedUpdated, err := tx.UserFederatedIdentity.Update().
				Where(
					userfederatedidentity.ProviderEQ(provider),
					userfederatedidentity.RevokedAtIsNil(),
					userfederatedidentity.HasIdentityWith(useridentity.UserIDEQ(resolved.UserID)),
				).
				SetRevokedAt(now).
				Save(ctx)
			if err != nil {
				return 0, err
			}

			userIdentityUpdated, err := tx.UserIdentity.Update().
				Where(
					useridentity.UserID(resolved.UserID),
					useridentity.Provider(provider),
					useridentity.RevokedAtIsNil(),
				).
				SetRevokedAt(now).
				Save(ctx)
			if err != nil {
				return 0, err
			}

			total := federatedUpdated + userIdentityUpdated
			if total == 0 {
				return 0, nil
			}
			actor := resolved.UserID
			err = authnaudit.Write(ctx, tx, audit.Entry{
				ActorID:      &actor,
				Action:       audit.ActionFederatedIdentityRevoke,
				ResourceType: audit.ResourceFederatedIdentity,
				ResourceID:   resolved.UserID.String(),
				Changes:      audit.Payload(map[string]any{"provider": provider}),
			})
			if err != nil {
				return 0, err
			}
			return total, nil
		})
	if err != nil {
		return nil, err
	}
	if revokedCount == 0 {
		return nil, status.Error(codes.NotFound, "federated identity not found")
	}

	// Publish account unlinked event (best-effort).
	if email := g.primaryEmail(ctx, resolved.UserID); email != "" {
		meta, _ := clientmeta.FromContext(ctx)
		g.notifyAccountUnlinked(ctx, email, provider, session.SessionMetadata{
			Locale:   meta.Locale,
			Timezone: meta.Timezone,
		})
	}

	out := &pb.RevokeLinkedIdentityResponse{}
	out.SetSuccess(true)
	return out, nil
}

func (g *GRPCHandler) RevokeSession(
	ctx context.Context,
	req *pb.RevokeSessionRequest,
) (*pb.RevokeSessionResponse, error) {
	// Wire token validated upstream by AuthnSessionPrincipalInterceptor.
	wire, _ := grpcutils.WireSessionTokenFromContext(ctx)

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
