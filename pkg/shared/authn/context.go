package authn

import (
	"context"

	"github.com/google/uuid"

	"sanzi.io/muid/pkg/audit"
	"sanzi.io/muid/pkg/log"
)

type authenticatedUserIDKey struct{}

// WithAuthenticatedUserID stores the authenticated user id on the context.
func WithAuthenticatedUserID(ctx context.Context, id uuid.UUID) context.Context {
	if ctx == nil || id == uuid.Nil {
		return ctx
	}
	return context.WithValue(ctx, authenticatedUserIDKey{}, id)
}

// AuthenticatedUserIDFromContext returns the authenticated user id stored on ctx.
func AuthenticatedUserIDFromContext(ctx context.Context) (uuid.UUID, bool) {
	if ctx == nil {
		return uuid.Nil, false
	}
	id, ok := ctx.Value(authenticatedUserIDKey{}).(uuid.UUID)
	return id, ok && id != uuid.Nil
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
