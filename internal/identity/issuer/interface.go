package issuer

import (
	"context"
	"time"

	"github.com/google/uuid"
	sessionpb "sanzi.io/muid/api/proto/authn/v1/session"
	"sanzi.io/muid/internal/session"
)

type ResolvedSession struct {
	SessionID uuid.UUID
	UserID    uuid.UUID
	ExpiresAt time.Time
	IssuedAt  time.Time
	// Email is the primary email address for the authenticated user.
	// Populated from UserRef on resolution; empty when unavailable.
	Email string
}

type SessionIssuer interface {
	CreateSession(ctx context.Context, userID uuid.UUID, metadata session.SessionMetadata) (*sessionpb.AuthenticatedResult, error)
	ResolveSessionToken(ctx context.Context, wireToken string) (ResolvedSession, error)
	RevokeSessionToken(ctx context.Context, wireToken string) error
	ExtendSession(ctx context.Context, wireToken string) (*sessionpb.SessionContext, error)
	AuthenticatedResultFromResolved(resolved ResolvedSession) *sessionpb.AuthenticatedResult
	AuthenticatedPrincipalFromResolved(resolved ResolvedSession) *sessionpb.AuthenticatedPrincipal
}
