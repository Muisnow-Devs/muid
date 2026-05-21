package account

import (
	"context"
	"time"

	"github.com/google/uuid"
	profilepb "sanzi.io/muid/api/proto/profile/v1"
	"sanzi.io/muid/internal/authn/ent"
	"sanzi.io/muid/internal/session"
)

// Store holds shared Ent and Profile dependencies for account domain services.
type Store struct {
	DB *ent.Client

	Profile profilepb.ProfileServiceClient
	// ProfileCallTimeout bounds each Profile RPC when non-zero; otherwise a default is used in callers.
	ProfileCallTimeout time.Duration

	// SessionCache is optional; when set, session resolution uses Redis with TTL <= session expiry.
	SessionCache session.SessionCache
}

func (s *Store) profileTimeout() time.Duration {
	if s.ProfileCallTimeout > 0 {
		return s.ProfileCallTimeout
	}
	return 10 * time.Second
}

func (s *Store) touchLastLogin(ctx context.Context, userID uuid.UUID) error {
	return s.DB.UserRef.UpdateOneID(userID).SetLastLoginAt(time.Now()).Exec(ctx)
}
