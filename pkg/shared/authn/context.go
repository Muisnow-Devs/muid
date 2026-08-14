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

// EnrichRequiredAuthenticatedUser enriches a verified request principal with
// logging and audit context.
func EnrichRequiredAuthenticatedUser(ctx context.Context) (context.Context, uuid.UUID, error) {
	id, ok := grpcutils.RequestUserIDFromContext(ctx)
	if !ok {
		return ctx, uuid.Nil, GRPCMissingAuthenticatedPrincipal()
	}
	ctx = log.WithAttrs(ctx, log.UserID(id))
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
