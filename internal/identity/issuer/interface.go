package issuer

import (
	"context"
	"time"

	"github.com/google/uuid"
	sessionpb "sanzi.io/muid/api/proto/authn/v1/session"
)

type ResolvedSession struct {
	SessionID uuid.UUID
	UserID    uuid.UUID
	ExpiresAt time.Time
	IssuedAt  time.Time
}

type SessionIssuer interface {
	CreateSession(ctx context.Context, userID uuid.UUID) (*sessionpb.AuthenticatedResult, error)
	ResolveSessionToken(ctx context.Context, wireToken string) (ResolvedSession, error)
	RevokeSessionToken(ctx context.Context, wireToken string) error
	ExtendSession(ctx context.Context, wireToken string) (*sessionpb.SessionContext, error)
	AuthenticatedResultFromResolved(
		wireToken string,
		resolved ResolvedSession,
	) *sessionpb.AuthenticatedResult
	AuthenticatedPrincipalFromResolved(resolved ResolvedSession) *sessionpb.AuthenticatedPrincipal
}
