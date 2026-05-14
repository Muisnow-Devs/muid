package account

import (
	"context"
	"time"

	"github.com/google/uuid"
	profilepb "sanzi.io/muid/api/proto/profile/v1"
	"sanzi.io/muid/internal/authn/ent"
)

// Services wires Ent persistence and the Profile gRPC client for signup flows.
type Services struct {
	DB *ent.Client

	Profile profilepb.ProfileServiceClient
	// ProfileCallTimeout bounds each Profile RPC when non-zero; otherwise a default is used in callers.
	ProfileCallTimeout time.Duration
}

func (s *Services) touchLastLogin(ctx context.Context, userID uuid.UUID) error {
	return s.DB.UserRef.UpdateOneID(userID).SetLastLoginAt(time.Now()).Exec(ctx)
}

func (s *Services) profileTimeout() time.Duration {
	if s.ProfileCallTimeout > 0 {
		return s.ProfileCallTimeout
	}
	return 10 * time.Second
}
