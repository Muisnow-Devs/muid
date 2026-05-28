package resolver

import (
	"context"

	"github.com/google/uuid"
	"sanzi.io/muid/api/proto/shared/v1/claims"
)

type UserResolution struct {
	UserID   uuid.UUID
	Created  bool
	Existing bool
}

type UserResolver interface {
	ResolveUser(ctx context.Context, identity *claims.IdentityInformation) (UserResolution, error)
}
