package authzclient

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	authzpb "sanzi.io/muid/api/proto/authz/v1"
	"sanzi.io/muid/pkg/shared/authzmodel"
)

// PlatformChecker checks platform-wide permissions through AuthzService.
type PlatformChecker struct {
	client authzpb.AuthzServiceClient
}

// NewPlatformChecker validates and constructs a platform permission client.
func NewPlatformChecker(client authzpb.AuthzServiceClient) (*PlatformChecker, error) {
	if client == nil {
		return nil, ErrInvalidConfig
	}
	return &PlatformChecker{client: client}, nil
}

// CheckPermission reports whether userID currently holds permission.
func (c *PlatformChecker) CheckPermission(
	ctx context.Context,
	userID uuid.UUID,
	permission string,
) (bool, error) {
	if c == nil || c.client == nil {
		return false, ErrInvalidConfig
	}
	if userID == uuid.Nil {
		return false, fmt.Errorf("authzclient: invalid user id")
	}
	if !authzmodel.ValidPermission(permission) {
		return false, authzmodel.ErrInvalidPermission
	}

	req := &authzpb.CheckPlatformPermissionRequest{}
	req.SetUserId(userID.String())
	req.SetPermission(permission)
	resp, err := c.client.CheckPlatformPermission(ctx, req)
	if err != nil {
		return false, err
	}
	return resp.GetAllowed(), nil
}
