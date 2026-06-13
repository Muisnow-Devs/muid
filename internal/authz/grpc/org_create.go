package authzgrpc

import (
	"context"

	"github.com/google/uuid"

	profilepb "sanzi.io/muid/api/proto/profile/v1"
	"sanzi.io/muid/internal/authz/policy"
	grpcutils "sanzi.io/muid/pkg/grpc_utils"
	"sanzi.io/muid/pkg/log"
)

// createOrganization creates the organization (with owner, roles, and casbin
// grouping) and then, when a profile client is configured, creates its
// editable profile in the profile service. The profile call happens after the
// authz transaction commits; if it fails the organization still exists, so the
// failure is logged and surfaced as an internal error for the caller to retry.
func createOrganization(
	ctx context.Context,
	manager *policy.Manager,
	profileClient profilepb.OrganizationProfileServiceClient,
	name, slug, description string,
	ownerUserID uuid.UUID,
) (uuid.UUID, error) {
	organizationID, err := manager.CreateOrganization(ctx, name, description, ownerUserID)
	if err != nil {
		return uuid.Nil, mapPolicyError(ctx, "authz create organization", err)
	}

	if profileClient == nil {
		return organizationID, nil
	}

	req := &profilepb.CreateOrganizationProfileRequest{}
	req.SetOrganizationId(organizationID.String())
	req.SetDisplayName(name)
	req.SetSlug(slug)
	req.SetDescription(description)
	_, err = profileClient.CreateOrganizationProfile(ctx, req)
	if err != nil {
		log.LogUnexpected(ctx, "authz create organization profile", err.Error())
		return uuid.Nil, grpcutils.GRPCInternalError()
	}

	return organizationID, nil
}
