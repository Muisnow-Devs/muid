package profilegrpc

import (
	"context"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "sanzi.io/muid/api/proto/profile/v1"
	"sanzi.io/muid/internal/profile/core"
	sharedauthn "sanzi.io/muid/pkg/shared/authn"
)

// orgManagePermission gates organization-profile edits; it belongs to the
// authz namespace (see CLAUDE.md: permissions are "service/method.action").
const orgManagePermission = "authz/org.manage"

// OrgPermissionEnforcer decides organization-scoped permissions for the
// caller. Satisfied by *authzclient.Enforcer.
type OrgPermissionEnforcer interface {
	Enforce(ctx context.Context, userID, organizationID uuid.UUID, permission string) (bool, error)
}

// OrganizationGRPCHandler implements OrganizationProfileService. When enforcer
// is nil, mutating RPCs report Unavailable (permission checks unconfigured).
type OrganizationGRPCHandler struct {
	pb.UnimplementedOrganizationProfileServiceServer

	mgr      *core.Manager
	enforcer OrgPermissionEnforcer
}

func NewOrganizationGRPCHandler(
	mgr *core.Manager,
	enforcer OrgPermissionEnforcer,
) pb.OrganizationProfileServiceServer {
	return &OrganizationGRPCHandler{mgr: mgr, enforcer: enforcer}
}

func (h *OrganizationGRPCHandler) CreateOrganizationProfile(
	ctx context.Context,
	req *pb.CreateOrganizationProfileRequest,
) (*pb.CreateOrganizationProfileResponse, error) {
	organizationID, err := uuid.Parse(req.GetOrganizationId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid organization id")
	}

	profile, err := h.mgr.CreateOrganizationProfile(ctx,
		organizationID, req.GetDisplayName(), req.GetSlug(), req.GetDescription())
	if err != nil {
		return nil, mapOrganizationProfileError(ctx, "organization profile create", err)
	}

	out := &pb.CreateOrganizationProfileResponse{}
	out.SetProfile(organizationProfileView(profile))
	return out, nil
}

func (h *OrganizationGRPCHandler) GetOrganizationProfile(
	ctx context.Context,
	req *pb.GetOrganizationProfileRequest,
) (*pb.GetOrganizationProfileResponse, error) {
	organizationID, err := uuid.Parse(req.GetOrganizationId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid organization id")
	}

	profile, err := h.mgr.GetOrganizationProfile(ctx, organizationID)
	if err != nil {
		return nil, mapOrganizationProfileError(ctx, "organization profile get", err)
	}

	out := &pb.GetOrganizationProfileResponse{}
	out.SetProfile(organizationProfileView(profile))
	return out, nil
}

func (h *OrganizationGRPCHandler) UpdateOrganizationProfile(
	ctx context.Context,
	req *pb.UpdateOrganizationProfileRequest,
) (*pb.UpdateOrganizationProfileResponse, error) {
	callerID, err := sharedauthn.RequiredAuthenticatedUserIDFromContext(ctx)
	if err != nil {
		return nil, err
	}
	organizationID, err := uuid.Parse(req.GetOrganizationId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid organization id")
	}

	if h.enforcer == nil {
		return nil, status.Error(
			codes.Unavailable,
			"organization permission checks are not configured (set PROFILE_AUTHZ_INTERNAL_GRPC_ADDR)",
		)
	}
	allowed, err := h.enforcer.Enforce(ctx, callerID, organizationID, orgManagePermission)
	if err != nil {
		return nil, mapOrganizationProfileError(ctx, "organization profile authorize", err)
	}
	if !allowed {
		return nil, status.Error(codes.PermissionDenied, "permission denied")
	}

	profile, err := h.mgr.UpdateOrganizationProfile(ctx, organizationID,
		req.GetUpdateMask(), req.GetDisplayName(), req.GetSlug(), req.GetDescription())
	if err != nil {
		return nil, mapOrganizationProfileError(ctx, "organization profile update", err)
	}

	out := &pb.UpdateOrganizationProfileResponse{}
	out.SetProfile(organizationProfileView(profile))
	return out, nil
}

func organizationProfileView(p core.OrganizationProfile) *pb.OrganizationProfileView {
	view := &pb.OrganizationProfileView{}
	view.SetOrganizationId(p.OrganizationID.String())
	view.SetSlug(p.Slug)
	view.SetDisplayName(p.DisplayName)
	view.SetDescription(p.Description)
	view.SetCreatedAt(timestamppb.New(p.CreatedAt))
	view.SetUpdatedAt(timestamppb.New(p.UpdatedAt))
	return view
}
