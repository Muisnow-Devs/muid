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

// AdminHandler implements AuthzAdminService, the IdP/platform-management
// surface. It performs no per-RPC authorization and is registered only on
// the internal listener.
type AdminHandler struct {
	pb.UnimplementedAuthzAdminServiceServer

	manager       *policy.Manager
	profileClient profilepb.OrganizationProfileServiceClient
}

func NewAdminHandler(config HandlerConfig) pb.AuthzAdminServiceServer {
	return &AdminHandler{manager: config.Manager, profileClient: config.ProfileClient}
}

func (h *AdminHandler) CreateOrganization(
	ctx context.Context,
	req *pb.CreateOrganizationRequest,
) (*pb.CreateOrganizationResponse, error) {
	ownerUserID, err := uuid.Parse(req.GetOwnerUserId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid owner user id")
	}

	organizationID, err := createOrganization(ctx, h.manager, h.profileClient,
		req.GetName(), req.GetSlug(), req.GetDescription(), ownerUserID)
	if err != nil {
		return nil, err
	}

	out := &pb.CreateOrganizationResponse{}
	out.SetOrganizationId(organizationID.String())
	return out, nil
}

func (h *AdminHandler) DeleteOrganization(
	ctx context.Context,
	req *pb.DeleteOrganizationRequest,
) (*pb.DeleteOrganizationResponse, error) {
	organizationID, err := parseOrganizationID(req.GetOrganizationId())
	if err != nil {
		return nil, err
	}

	err = h.manager.DeleteOrganization(ctx, organizationID)
	if err != nil {
		return nil, mapPolicyError(ctx, "authz delete organization", err)
	}
	return &pb.DeleteOrganizationResponse{}, nil
}

func (h *AdminHandler) SetOrganizationMember(
	ctx context.Context,
	req *pb.SetOrganizationMemberRequest,
) (*pb.SetOrganizationMemberResponse, error) {
	organizationID, err := parseOrganizationID(req.GetOrganizationId())
	if err != nil {
		return nil, err
	}
	userID, err := uuid.Parse(req.GetUserId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid user id")
	}

	err = h.manager.SetMember(ctx, organizationID, userID, req.GetRole())
	if err != nil {
		return nil, mapPolicyError(ctx, "authz set organization member", err)
	}
	return &pb.SetOrganizationMemberResponse{}, nil
}

func (h *AdminHandler) ListCasbinRules(
	ctx context.Context,
	req *pb.ListCasbinRulesRequest,
) (*pb.ListCasbinRulesResponse, error) {
	rules, nextPageToken, revision, err := h.manager.CasbinRules(ctx,
		req.GetPtype(), req.GetDomain(), int(req.GetPageSize()), req.GetPageToken())
	if err != nil {
		return nil, mapPolicyError(ctx, "authz list casbin rules", err)
	}

	out := &pb.ListCasbinRulesResponse{}
	out.SetRules(rulesToProto(rules))
	out.SetNextPageToken(nextPageToken)
	out.SetRevisionId(revisionToProto(revision))
	return out, nil
}

func (h *AdminHandler) AddRawPolicies(
	ctx context.Context,
	req *pb.AddRawPoliciesRequest,
) (*pb.AddRawPoliciesResponse, error) {
	err := h.manager.AddRawRules(ctx, rulesFromProto(req.GetRules()))
	if err != nil {
		return nil, mapPolicyError(ctx, "authz add raw policies", err)
	}
	return &pb.AddRawPoliciesResponse{}, nil
}

func (h *AdminHandler) RemoveRawPolicies(
	ctx context.Context,
	req *pb.RemoveRawPoliciesRequest,
) (*pb.RemoveRawPoliciesResponse, error) {
	err := h.manager.RemoveRawRules(ctx, rulesFromProto(req.GetRules()))
	if err != nil {
		return nil, mapPolicyError(ctx, "authz remove raw policies", err)
	}
	return &pb.RemoveRawPoliciesResponse{}, nil
}

func (h *AdminHandler) ReloadPolicyConfig(
	ctx context.Context,
	_ *pb.ReloadPolicyConfigRequest,
) (*pb.ReloadPolicyConfigResponse, error) {
	changed, revision, err := h.manager.Reconcile(ctx)
	if err != nil {
		return nil, mapPolicyError(ctx, "authz reload policy config", err)
	}

	out := &pb.ReloadPolicyConfigResponse{}
	out.SetChanged(changed)
	out.SetRevisionId(revisionToProto(revision))
	return out, nil
}
