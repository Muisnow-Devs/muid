package authzgrpc

import (
	"context"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "sanzi.io/muid/api/proto/authz/v1"
	profilepb "sanzi.io/muid/api/proto/profile/v1"
	"sanzi.io/muid/internal/authz/policy"
)

// UserHandler implements AuthzUserService, the default end-user surface on
// the public listener. Caller identity comes from the verified request principal.
type UserHandler struct {
	pb.UnimplementedAuthzUserServiceServer

	manager       *policy.Manager
	profileClient profilepb.OrganizationProfileServiceClient
}

func NewUserHandler(config HandlerConfig) pb.AuthzUserServiceServer {
	return &UserHandler{manager: config.Manager, profileClient: config.ProfileClient}
}

// CreateMyOrganization creates an organization with the caller seeded as its
// first owner, then provisions its profile in the profile service.
func (h *UserHandler) CreateMyOrganization(
	ctx context.Context,
	req *pb.CreateMyOrganizationRequest,
) (*pb.CreateMyOrganizationResponse, error) {
	userID, err := caller(ctx)
	if err != nil {
		return nil, err
	}

	organizationID, err := createOrganization(ctx, h.manager, h.profileClient,
		req.GetName(), req.GetSlug(), req.GetDescription(), userID)
	if err != nil {
		return nil, err
	}

	out := &pb.CreateMyOrganizationResponse{}
	out.SetOrganizationId(organizationID.String())
	return out, nil
}

// caller returns the gateway-verified user id.
func caller(ctx context.Context) (uuid.UUID, error) {
	userID, ok := UserIDFromContext(ctx)
	if !ok {
		return uuid.Nil, status.Error(codes.Unauthenticated, "user identity required")
	}
	return userID, nil
}

func parseOrganizationID(raw string) (uuid.UUID, error) {
	organizationID, err := uuid.Parse(raw)
	if err != nil {
		return uuid.Nil, status.Error(codes.InvalidArgument, "invalid organization id")
	}
	return organizationID, nil
}

func (h *UserHandler) ListMyOrganizations(
	ctx context.Context,
	req *pb.ListMyOrganizationsRequest,
) (*pb.ListMyOrganizationsResponse, error) {
	userID, err := caller(ctx)
	if err != nil {
		return nil, err
	}

	memberships, nextPageToken, err := h.manager.UserOrganizations(
		ctx, userID, int(req.GetPageSize()), req.GetPageToken())
	if err != nil {
		return nil, mapPolicyError(ctx, "authz list my organizations", err)
	}

	views := make([]*pb.OrganizationMembershipView, 0, len(memberships))
	for _, m := range memberships {
		view := &pb.OrganizationMembershipView{}
		view.SetOrganizationId(m.OrganizationID.String())
		view.SetName(m.Name)
		view.SetDescription(m.Description)
		view.SetRole(m.Role)
		views = append(views, view)
	}

	out := &pb.ListMyOrganizationsResponse{}
	out.SetOrganizations(views)
	out.SetNextPageToken(nextPageToken)
	return out, nil
}

func (h *UserHandler) ListMyPermissions(
	ctx context.Context,
	req *pb.ListMyPermissionsRequest,
) (*pb.ListMyPermissionsResponse, error) {
	userID, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	organizationID, err := parseOrganizationID(req.GetOrganizationId())
	if err != nil {
		return nil, err
	}

	permissions, err := h.manager.ImplicitPermissions(ctx, userID, organizationID)
	if err != nil {
		return nil, mapPolicyError(ctx, "authz list my permissions", err)
	}

	out := &pb.ListMyPermissionsResponse{}
	out.SetPermissions(permissions)
	return out, nil
}

func (h *UserHandler) CheckMyPermission(
	ctx context.Context,
	req *pb.CheckMyPermissionRequest,
) (*pb.CheckMyPermissionResponse, error) {
	userID, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	organizationID, err := parseOrganizationID(req.GetOrganizationId())
	if err != nil {
		return nil, err
	}

	allowed, err := h.manager.Enforce(ctx, userID, organizationID, req.GetPermission())
	if err != nil {
		return nil, mapPolicyError(ctx, "authz check my permission", err)
	}

	out := &pb.CheckMyPermissionResponse{}
	out.SetAllowed(allowed)
	return out, nil
}
