package policy

import (
	"context"

	"github.com/google/uuid"

	"sanzi.io/muid/internal/authn/ent"
	"sanzi.io/muid/internal/authn/ent/oidcclientaccessgrant"
	"sanzi.io/muid/pkg/authzclient"
)

// LocalEnforcerAccess answers membership and permission checks through the
// service-local casbin enforcer (pkg/authzclient), which replicates authn's
// permission relations from authz and caches user roles — no per-check RPC.
type LocalEnforcerAccess struct {
	Enforcer *authzclient.Enforcer
}

func (a LocalEnforcerAccess) IsMember(
	ctx context.Context,
	organizationID, userID uuid.UUID,
) (bool, error) {
	return a.Enforcer.IsMember(ctx, userID, organizationID)
}

// HasPermission checks a "namespace/resource.action" permission locally.
func (a LocalEnforcerAccess) HasPermission(
	ctx context.Context,
	organizationID, userID uuid.UUID,
	permission string,
) (bool, error) {
	return a.Enforcer.Enforce(ctx, userID, organizationID, permission)
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
