package policy

import (
	"context"

	"github.com/google/uuid"

	authzpb "sanzi.io/muid/api/proto/authz/v1"
	"sanzi.io/muid/internal/authn/ent"
	"sanzi.io/muid/internal/authn/ent/oidcclientaccessgrant"
)

// GRPCMembership answers membership checks through the authz service.
type GRPCMembership struct {
	Client authzpb.AuthzServiceClient
}

func (m GRPCMembership) IsMember(
	ctx context.Context,
	organizationID, userID uuid.UUID,
) (bool, error) {
	req := &authzpb.CheckOrganizationMembershipRequest{}
	req.SetOrganizationId(organizationID.String())
	req.SetUserId(userID.String())

	resp, err := m.Client.CheckOrganizationMembership(ctx, req)
	if err != nil {
		return false, err
	}
	return resp.GetIsMember(), nil
}

// HasPermission checks a "resource:action" permission through the authz
// service.
func (m GRPCMembership) HasPermission(
	ctx context.Context,
	organizationID, userID uuid.UUID,
	permission string,
) (bool, error) {
	req := &authzpb.CheckOrganizationPermissionRequest{}
	req.SetOrganizationId(organizationID.String())
	req.SetUserId(userID.String())
	req.SetPermission(permission)

	resp, err := m.Client.CheckOrganizationPermission(ctx, req)
	if err != nil {
		return false, err
	}
	return resp.GetAllowed(), nil
}

// EntAllowlist answers private-client allowlist checks from the authn DB.
type EntAllowlist struct {
	DB *ent.Client
}

func (a EntAllowlist) HasAccess(
	ctx context.Context,
	clientRefID, userID uuid.UUID,
) (bool, error) {
	return a.DB.OIDCClientAccessGrant.Query().
		Where(
			oidcclientaccessgrant.ClientRefID(clientRefID),
			oidcclientaccessgrant.UserID(userID),
		).
		Exist(ctx)
}
