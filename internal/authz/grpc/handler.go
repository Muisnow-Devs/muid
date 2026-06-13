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

// GRPCHandler implements AuthzService: internal service-to-service checks
// and relation loading for per-service local enforcers.
type GRPCHandler struct {
	pb.UnimplementedAuthzServiceServer

	manager *policy.Manager
}

type HandlerConfig struct {
	Manager *policy.Manager
	// ProfileClient creates the organization's profile (slug/display
	// name/description) after the org is created. Nil disables that step
	// (the org is still created without a profile row).
	ProfileClient profilepb.OrganizationProfileServiceClient
}

func NewGRPCHandler(config HandlerConfig) pb.AuthzServiceServer {
	return &GRPCHandler{manager: config.Manager}
}

func (g *GRPCHandler) CheckOrganizationMembership(
	ctx context.Context,
	req *pb.CheckOrganizationMembershipRequest,
) (*pb.CheckOrganizationMembershipResponse, error) {
	organizationID, userID, err := parseOrganizationAndUser(
		req.GetOrganizationId(),
		req.GetUserId(),
	)
	if err != nil {
		return nil, err
	}

	isMember, err := g.manager.IsMember(ctx, organizationID, userID)
	if err != nil {
		return nil, mapPolicyError(ctx, "authz check membership", err)
	}

	out := &pb.CheckOrganizationMembershipResponse{}
	out.SetIsMember(isMember)
	return out, nil
}

func (g *GRPCHandler) CheckOrganizationPermission(
	ctx context.Context,
	req *pb.CheckOrganizationPermissionRequest,
) (*pb.CheckOrganizationPermissionResponse, error) {
	organizationID, userID, err := parseOrganizationAndUser(
		req.GetOrganizationId(),
		req.GetUserId(),
	)
	if err != nil {
		return nil, err
	}

	allowed, isMember, err := g.manager.CheckPermission(
		ctx,
		organizationID,
		userID,
		req.GetPermission(),
	)
	if err != nil {
		return nil, mapPolicyError(ctx, "authz check permission", err)
	}

	out := &pb.CheckOrganizationPermissionResponse{}
	out.SetAllowed(allowed)
	out.SetIsMember(isMember)
	return out, nil
}

func (g *GRPCHandler) ListNamespacePolicies(
	ctx context.Context,
	req *pb.ListNamespacePoliciesRequest,
) (*pb.ListNamespacePoliciesResponse, error) {
	rules, nextPageToken, revision, err := g.manager.NamespacePolicies(
		ctx,
		req.GetNamespace(),
		int(req.GetPageSize()),
		req.GetPageToken(),
	)
	if err != nil {
		return nil, mapPolicyError(ctx, "authz list namespace policies", err)
	}

	out := &pb.ListNamespacePoliciesResponse{}
	out.SetRules(rulesToProto(rules))
	out.SetNextPageToken(nextPageToken)
	out.SetRevisionId(revisionToProto(revision))
	return out, nil
}

func (g *GRPCHandler) ListUserOrganizationRoles(
	ctx context.Context,
	req *pb.ListUserOrganizationRolesRequest,
) (*pb.ListUserOrganizationRolesResponse, error) {
	organizationID, userID, err := parseOrganizationAndUser(
		req.GetOrganizationId(),
		req.GetUserId(),
	)
	if err != nil {
		return nil, err
	}

	roles, isMember, err := g.manager.UserRoles(ctx, userID, organizationID)
	if err != nil {
		return nil, mapPolicyError(ctx, "authz list user roles", err)
	}

	out := &pb.ListUserOrganizationRolesResponse{}
	out.SetRoles(roles)
	out.SetIsMember(isMember)
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

// rulesToProto converts policy rules to wire PolicyRule messages.
func rulesToProto(rules []policy.Rule) []*pb.PolicyRule {
	out := make([]*pb.PolicyRule, 0, len(rules))
	for _, r := range rules {
		msg := &pb.PolicyRule{}
		msg.SetPtype(r.Ptype)
		msg.SetValues(r.Values)
		out = append(out, msg)
	}
	return out
}

// rulesFromProto converts wire PolicyRule messages to policy rules.
func rulesFromProto(rules []*pb.PolicyRule) []policy.Rule {
	out := make([]policy.Rule, 0, len(rules))
	for _, msg := range rules {
		out = append(out, policy.Rule{Ptype: msg.GetPtype(), Values: msg.GetValues()})
	}
	return out
}

// revisionToProto renders a revision id ("" when none yet).
func revisionToProto(revision uuid.UUID) string {
	if revision == uuid.Nil {
		return ""
	}
	return revision.String()
}
