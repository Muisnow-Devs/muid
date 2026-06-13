package authzgrpc

import (
	"context"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "sanzi.io/muid/api/proto/authz/v1"
	"sanzi.io/muid/internal/authz/policy"
)

// OrgAdminHandler implements AuthzOrganizationAdminService on the public
// listener. Every RPC authorizes the caller in the target organization
// through the casbin enforcer before acting.
type OrgAdminHandler struct {
	pb.UnimplementedAuthzOrganizationAdminServiceServer

	manager *policy.Manager
}

func NewOrgAdminHandler(config HandlerConfig) pb.AuthzOrganizationAdminServiceServer {
	return &OrgAdminHandler{manager: config.Manager}
}

// authorize resolves the caller and enforces the required permission in the
// organization.
func (h *OrgAdminHandler) authorize(
	ctx context.Context,
	rawOrgID, permission string,
) (actorID, organizationID uuid.UUID, err error) {
	actorID, err = caller(ctx)
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	organizationID, err = parseOrganizationID(rawOrgID)
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}

	allowed, err := h.manager.Enforce(ctx, actorID, organizationID, permission)
	if err != nil {
		return uuid.Nil, uuid.Nil, mapPolicyError(ctx, "authz org admin authorize", err)
	}
	if !allowed {
		return uuid.Nil, uuid.Nil, status.Error(codes.PermissionDenied, "permission denied")
	}
	return actorID, organizationID, nil
}

func roleToProto(role policy.RoleInfo) *pb.RoleView {
	view := &pb.RoleView{}
	view.SetRoleId(role.ID.String())
	view.SetName(role.Name)
	view.SetDescription(role.Description)
	view.SetIsSystem(role.IsSystem)
	view.SetPermissions(role.Permissions)
	return view
}

func (h *OrgAdminHandler) CreateRole(
	ctx context.Context,
	req *pb.CreateRoleRequest,
) (*pb.CreateRoleResponse, error) {
	_, organizationID, err := h.authorize(ctx, req.GetOrganizationId(), policy.PermissionRoleWrite)
	if err != nil {
		return nil, err
	}

	role, err := h.manager.CreateRole(ctx, organizationID,
		req.GetName(), req.GetDescription(), req.GetPermissions())
	if err != nil {
		return nil, mapPolicyError(ctx, "authz create role", err)
	}

	out := &pb.CreateRoleResponse{}
	out.SetRole(roleToProto(role))
	return out, nil
}

func (h *OrgAdminHandler) UpdateRole(
	ctx context.Context,
	req *pb.UpdateRoleRequest,
) (*pb.UpdateRoleResponse, error) {
	_, organizationID, err := h.authorize(ctx, req.GetOrganizationId(), policy.PermissionRoleWrite)
	if err != nil {
		return nil, err
	}

	role, err := h.manager.UpdateRole(ctx, organizationID,
		req.GetName(), req.GetNewName(), req.GetDescription(), req.GetPermissions())
	if err != nil {
		return nil, mapPolicyError(ctx, "authz update role", err)
	}

	out := &pb.UpdateRoleResponse{}
	out.SetRole(roleToProto(role))
	return out, nil
}

func (h *OrgAdminHandler) DeleteRole(
	ctx context.Context,
	req *pb.DeleteRoleRequest,
) (*pb.DeleteRoleResponse, error) {
	_, organizationID, err := h.authorize(ctx, req.GetOrganizationId(), policy.PermissionRoleWrite)
	if err != nil {
		return nil, err
	}

	err = h.manager.DeleteRole(ctx, organizationID, req.GetName())
	if err != nil {
		return nil, mapPolicyError(ctx, "authz delete role", err)
	}
	return &pb.DeleteRoleResponse{}, nil
}

func (h *OrgAdminHandler) ListRoles(
	ctx context.Context,
	req *pb.ListRolesRequest,
) (*pb.ListRolesResponse, error) {
	_, organizationID, err := h.authorize(ctx, req.GetOrganizationId(), policy.PermissionRoleRead)
	if err != nil {
		return nil, err
	}

	roles, err := h.manager.Roles(ctx, organizationID)
	if err != nil {
		return nil, mapPolicyError(ctx, "authz list roles", err)
	}

	views := make([]*pb.RoleView, 0, len(roles))
	for _, role := range roles {
		views = append(views, roleToProto(role))
	}
	out := &pb.ListRolesResponse{}
	out.SetRoles(views)
	return out, nil
}

func (h *OrgAdminHandler) AddMember(
	ctx context.Context,
	req *pb.AddMemberRequest,
) (*pb.AddMemberResponse, error) {
	actorID, organizationID, err := h.authorize(
		ctx,
		req.GetOrganizationId(),
		policy.PermissionMemberWrite,
	)
	if err != nil {
		return nil, err
	}
	userID, err := uuid.Parse(req.GetUserId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid user id")
	}

	err = h.manager.AddMember(ctx, actorID, organizationID, userID, req.GetRole())
	if err != nil {
		return nil, mapPolicyError(ctx, "authz add member", err)
	}
	return &pb.AddMemberResponse{}, nil
}

func (h *OrgAdminHandler) RemoveMember(
	ctx context.Context,
	req *pb.RemoveMemberRequest,
) (*pb.RemoveMemberResponse, error) {
	actorID, organizationID, err := h.authorize(
		ctx,
		req.GetOrganizationId(),
		policy.PermissionMemberWrite,
	)
	if err != nil {
		return nil, err
	}
	userID, err := uuid.Parse(req.GetUserId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid user id")
	}

	err = h.manager.RemoveMember(ctx, actorID, organizationID, userID)
	if err != nil {
		return nil, mapPolicyError(ctx, "authz remove member", err)
	}
	return &pb.RemoveMemberResponse{}, nil
}

func (h *OrgAdminHandler) ChangeMemberRole(
	ctx context.Context,
	req *pb.ChangeMemberRoleRequest,
) (*pb.ChangeMemberRoleResponse, error) {
	actorID, organizationID, err := h.authorize(
		ctx,
		req.GetOrganizationId(),
		policy.PermissionMemberWrite,
	)
	if err != nil {
		return nil, err
	}
	userID, err := uuid.Parse(req.GetUserId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid user id")
	}

	err = h.manager.ChangeMemberRole(ctx, actorID, organizationID, userID, req.GetRole())
	if err != nil {
		return nil, mapPolicyError(ctx, "authz change member role", err)
	}
	return &pb.ChangeMemberRoleResponse{}, nil
}

func (h *OrgAdminHandler) ListMembers(
	ctx context.Context,
	req *pb.ListMembersRequest,
) (*pb.ListMembersResponse, error) {
	_, organizationID, err := h.authorize(ctx, req.GetOrganizationId(), policy.PermissionMemberRead)
	if err != nil {
		return nil, err
	}

	members, nextPageToken, err := h.manager.Members(
		ctx, organizationID, int(req.GetPageSize()), req.GetPageToken())
	if err != nil {
		return nil, mapPolicyError(ctx, "authz list members", err)
	}

	views := make([]*pb.MemberView, 0, len(members))
	for _, member := range members {
		view := &pb.MemberView{}
		view.SetUserId(member.UserID.String())
		view.SetRole(member.Role)
		view.SetCreatedAt(timestamppb.New(time.Unix(member.CreatedAt, 0)))
		views = append(views, view)
	}

	out := &pb.ListMembersResponse{}
	out.SetMembers(views)
	out.SetNextPageToken(nextPageToken)
	return out, nil
}
