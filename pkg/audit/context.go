package audit

import (
	"context"

	"github.com/google/uuid"
)

type actorCtxKey struct{}

// WithActor stashes the resolved caller id on ctx so writeAudit can record it
// without threading an actor parameter through every mutation. Identity
// interceptors call this once after resolving the caller. A nil id is a no-op
// (system / unauthenticated flows leave the actor unset).
func WithActor(ctx context.Context, id uuid.UUID) context.Context {
	if ctx == nil || id == uuid.Nil {
		return ctx
	}
	return context.WithValue(ctx, actorCtxKey{}, id)
}

// ActorFromContext returns the actor id stored by WithActor.
func ActorFromContext(ctx context.Context) (uuid.UUID, bool) {
	if ctx == nil {
		return uuid.Nil, false
	}
	id, ok := ctx.Value(actorCtxKey{}).(uuid.UUID)
	return id, ok && id != uuid.Nil
}
