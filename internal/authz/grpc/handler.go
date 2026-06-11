package authzgrpc

import (
	"context"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "sanzi.io/muid/api/proto/authz/v1"
	authzent "sanzi.io/muid/internal/authz/ent"
	"sanzi.io/muid/internal/authz/ent/organizationmember"
	"sanzi.io/muid/internal/authz/ent/organizationrole"
	"sanzi.io/muid/internal/authz/ent/rolepermission"
	grpcutils "sanzi.io/muid/pkg/grpc_utils"
	"sanzi.io/muid/pkg/log"
)

type GRPCHandler struct {
	pb.UnimplementedAuthzServiceServer

	db *authzent.Client
}

type HandlerConfig struct {
	DB *authzent.Client
}

func NewGRPCHandler(config HandlerConfig) pb.AuthzServiceServer {
	return &GRPCHandler{
		db: config.DB,
	}
}

func (g *GRPCHandler) CheckOrganizationMembership(
	ctx context.Context,
	req *pb.CheckOrganizationMembershipRequest,
) (*pb.CheckOrganizationMembershipResponse, error) {
	if g.db == nil {
		return nil, status.Error(codes.Unavailable, "database unavailable")
	}

	organizationID, userID, err := parseOrganizationAndUser(
		req.GetOrganizationId(),
		req.GetUserId(),
	)
	if err != nil {
		return nil, err
	}

	isMember, err := g.db.OrganizationMember.Query().
		Where(
			organizationmember.OrganizationID(organizationID),
			organizationmember.UserID(userID),
		).
		Exist(ctx)
	if err != nil {
		log.LogUnexpected(ctx, "authz check membership", err.Error(),
			log.UserID(userID))
		return nil, grpcutils.GRPCInternalError()
	}

	out := &pb.CheckOrganizationMembershipResponse{}
	out.SetIsMember(isMember)
	return out, nil
}

func (g *GRPCHandler) CheckOrganizationPermission(
	ctx context.Context,
	req *pb.CheckOrganizationPermissionRequest,
) (*pb.CheckOrganizationPermissionResponse, error) {
	if g.db == nil {
		return nil, status.Error(codes.Unavailable, "database unavailable")
	}

	organizationID, userID, err := parseOrganizationAndUser(
		req.GetOrganizationId(),
		req.GetUserId(),
	)
	if err != nil {
		return nil, err
	}

	member, err := g.db.OrganizationMember.Query().
		Where(
			organizationmember.OrganizationID(organizationID),
			organizationmember.UserID(userID),
		).
		Only(ctx)
	if authzent.IsNotFound(err) {
		out := &pb.CheckOrganizationPermissionResponse{}
		out.SetAllowed(false)
		out.SetIsMember(false)
		return out, nil
	}
	if err != nil {
		log.LogUnexpected(ctx, "authz check permission member", err.Error(),
			log.UserID(userID))
		return nil, grpcutils.GRPCInternalError()
	}

	allowed, err := g.db.RolePermission.Query().
		Where(
			rolepermission.Permission(req.GetPermission()),
			rolepermission.HasRoleWith(organizationrole.ID(member.RoleID)),
		).
		Exist(ctx)
	if err != nil {
		log.LogUnexpected(ctx, "authz check permission role", err.Error(),
			log.UserID(userID))
		return nil, grpcutils.GRPCInternalError()
	}

	out := &pb.CheckOrganizationPermissionResponse{}
	out.SetAllowed(allowed)
	out.SetIsMember(true)
	return out, nil
}

func parseOrganizationAndUser(rawOrgID, rawUserID string) (uuid.UUID, uuid.UUID, error) {
	organizationID, err := uuid.Parse(rawOrgID)
	if err != nil {
		return uuid.Nil, uuid.Nil, status.Error(codes.InvalidArgument, "invalid organization id")
	}
	userID, err := uuid.Parse(rawUserID)
	if err != nil {
		return uuid.Nil, uuid.Nil, status.Error(codes.InvalidArgument, "invalid user id")
	}
	return organizationID, userID, nil
}
