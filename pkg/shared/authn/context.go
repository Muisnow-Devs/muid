package authn

import (
	"context"

	"github.com/google/uuid"

	"sanzi.io/muid/pkg/audit"
	grpcutils "sanzi.io/muid/pkg/grpc_utils"
	"sanzi.io/muid/pkg/log"
)

// WithAuthenticatedUserID stores the authenticated user id on the context.
func WithAuthenticatedUserID(ctx context.Context, id uuid.UUID) context.Context {
	return grpcutils.WithRequestUserID(ctx, id)
}

// AuthenticatedUserIDFromContext returns the authenticated user id stored on ctx.
func AuthenticatedUserIDFromContext(ctx context.Context) (uuid.UUID, bool) {
	return grpcutils.RequestUserIDFromContext(ctx)
}

// EnrichRequiredAuthenticatedUser parses x-authn-user-id metadata, attaches log.UserID, and stores the id on ctx.
func EnrichRequiredAuthenticatedUser(ctx context.Context) (context.Context, uuid.UUID, error) {
	id, err := authenticatedUserIDFromMetadata(ctx)
	if err != nil {
		return ctx, uuid.Nil, err
	}
	ctx = log.WithAttrs(ctx, log.UserID(id))
	ctx = WithAuthenticatedUserID(ctx, id)
	ctx = audit.WithActor(ctx, id)
	return ctx, id, nil
}

// RequiredAuthenticatedUserIDFromContext returns the authenticated user id stored by middleware.
func RequiredAuthenticatedUserIDFromContext(ctx context.Context) (uuid.UUID, error) {
	id, ok := AuthenticatedUserIDFromContext(ctx)
	if !ok {
		return uuid.Nil, GRPCMissingAuthenticatedUserIDContext()
	}
	return id, nil
}
