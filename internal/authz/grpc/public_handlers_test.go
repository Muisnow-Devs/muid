package authzgrpc

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "sanzi.io/muid/api/proto/authz/v1"
	"sanzi.io/muid/internal/authz/policy"
)

// ctxAsUser injects the caller id the way UserIdentityInterceptor does.
func ctxAsUser(userID uuid.UUID) context.Context {
	return context.WithValue(context.Background(), userIDContextKey{}, userID)
}

func wantCode(t *testing.T, err error, want codes.Code) {
	t.Helper()
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("error %v is not a gRPC status", err)
	}
	if st.Code() != want {
		t.Fatalf("status code = %v, want %v (err: %v)", st.Code(), want, err)
	}
}

func TestUserIdentityInterceptor(t *testing.T) {
	t.Parallel()

	interceptor := UserIdentityInterceptor()
	publicMethod := "/" + pb.AuthzUserService_ServiceDesc.ServiceName + "/CheckMyPermission"
	internalMethod := "/" + pb.AuthzService_ServiceDesc.ServiceName + "/CheckOrganizationPermission"
	userID := uuid.New()

	tests := []struct {
		name       string
		fullMethod string
		md         metadata.MD
		wantErr    codes.Code
		wantUser   bool
	}{
		{
			name:       "valid identity",
			fullMethod: publicMethod,
			md:         metadata.Pairs(UserIDMetadataKey, userID.String()),
			wantUser:   true,
		},
		{
			name:       "missing metadata",
			fullMethod: publicMethod,
			wantErr:    codes.Unauthenticated,
		},
		{
			name:       "malformed user id",
			fullMethod: publicMethod,
			md:         metadata.Pairs(UserIDMetadataKey, "not-a-uuid"),
			wantErr:    codes.Unauthenticated,
		},
		{
			name:       "duplicated header",
			fullMethod: publicMethod,
			md: metadata.Pairs(
				UserIDMetadataKey, userID.String(),
				UserIDMetadataKey, uuid.New().String(),
			),
			wantErr: codes.Unauthenticated,
		},
		{
			name:       "internal method passes through without identity",
			fullMethod: internalMethod,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			if tc.md != nil {
				ctx = metadata.NewIncomingContext(ctx, tc.md)
			}

			var gotUser uuid.UUID
			var gotOK bool
			handler := func(ctx context.Context, _ any) (any, error) {
				gotUser, gotOK = UserIDFromContext(ctx)
				return nil, nil
			}

			_, err := interceptor(
				ctx,
				nil,
				&grpc.UnaryServerInfo{FullMethod: tc.fullMethod},
				handler,
			)
			if tc.wantErr != codes.OK {
				wantCode(t, err, tc.wantErr)
				return
			}
			if err != nil {
				t.Fatalf("interceptor error = %v, want nil", err)
			}
			if gotOK != tc.wantUser {
				t.Fatalf("handler saw identity = %v, want %v", gotOK, tc.wantUser)
			}
			if tc.wantUser && gotUser != userID {
				t.Errorf("handler user id = %v, want %v", gotUser, userID)
			}
		})
	}
}

func TestOrgAdminHandlerAuthorization(t *testing.T) {
	fixture := newOrgFixture(t, "authzorgadminhandler")
	handler := NewOrgAdminHandler(HandlerConfig{Manager: fixture.manager})

	createReq := &pb.CreateRoleRequest{}
	createReq.SetOrganizationId(fixture.organizationID.String())
	createReq.SetName("auditors")
	createReq.SetPermissions([]string{"authz/org.view"})

	t.Run("member without role.manage is denied", func(t *testing.T) {
		_, err := handler.CreateRole(ctxAsUser(fixture.member), createReq)
		wantCode(t, err, codes.PermissionDenied)
	})

	t.Run("non-member is denied", func(t *testing.T) {
		_, err := handler.CreateRole(ctxAsUser(fixture.nonMember), createReq)
		wantCode(t, err, codes.PermissionDenied)
	})

	t.Run("missing identity is unauthenticated", func(t *testing.T) {
		_, err := handler.CreateRole(context.Background(), createReq)
		wantCode(t, err, codes.Unauthenticated)
	})

	t.Run("admin creates and lists roles", func(t *testing.T) {
		resp, err := handler.CreateRole(ctxAsUser(fixture.admin), createReq)
		if err != nil {
			t.Fatalf("CreateRole as admin: %v", err)
		}
		if resp.GetRole().GetName() != "auditors" {
			t.Errorf("created role name = %q, want auditors", resp.GetRole().GetName())
		}

		listReq := &pb.ListRolesRequest{}
		listReq.SetOrganizationId(fixture.organizationID.String())
		// role.view is a member grant.
		listResp, err := handler.ListRoles(ctxAsUser(fixture.member), listReq)
		if err != nil {
			t.Fatalf("ListRoles as member: %v", err)
		}
		// Four system roles plus the new custom role.
		if got := len(listResp.GetRoles()); got != 5 {
			t.Errorf("role count = %d, want 5", got)
		}
	})

	t.Run("member management guards map to statuses", func(t *testing.T) {
		// Demoting the last owner fails with FailedPrecondition.
		changeReq := &pb.ChangeMemberRoleRequest{}
		changeReq.SetOrganizationId(fixture.organizationID.String())
		changeReq.SetUserId(fixture.owner.String())
		changeReq.SetRole("member")
		_, err := handler.ChangeMemberRole(ctxAsUser(fixture.owner), changeReq)
		wantCode(t, err, codes.FailedPrecondition)

		// An admin (manager grant holder) cannot grant owner.
		grantReq := &pb.ChangeMemberRoleRequest{}
		grantReq.SetOrganizationId(fixture.organizationID.String())
		grantReq.SetUserId(fixture.member.String())
		grantReq.SetRole("owner")
		_, err = handler.ChangeMemberRole(ctxAsUser(fixture.admin), grantReq)
		wantCode(t, err, codes.PermissionDenied)

		// Removing an unknown member is NotFound.
		removeReq := &pb.RemoveMemberRequest{}
		removeReq.SetOrganizationId(fixture.organizationID.String())
		removeReq.SetUserId(uuid.New().String())
		_, err = handler.RemoveMember(ctxAsUser(fixture.admin), removeReq)
		wantCode(t, err, codes.NotFound)
	})
}

func TestUserHandler(t *testing.T) {
	fixture := newOrgFixture(t, "authzuserhandler")
	handler := NewUserHandler(HandlerConfig{Manager: fixture.manager})
	ctx := context.Background()

	t.Run("list my organizations", func(t *testing.T) {
		req := &pb.ListMyOrganizationsRequest{}
		resp, err := handler.ListMyOrganizations(ctxAsUser(fixture.member), req)
		if err != nil {
			t.Fatalf("ListMyOrganizations: %v", err)
		}
		if len(resp.GetOrganizations()) != 1 {
			t.Fatalf("organization count = %d, want 1", len(resp.GetOrganizations()))
		}
		org := resp.GetOrganizations()[0]
		if org.GetOrganizationId() != fixture.organizationID.String() || org.GetRole() != "member" {
			t.Errorf("membership view = (%s, %s), want (%s, member)",
				org.GetOrganizationId(), org.GetRole(), fixture.organizationID)
		}
	})

	t.Run("check my permission", func(t *testing.T) {
		req := &pb.CheckMyPermissionRequest{}
		req.SetOrganizationId(fixture.organizationID.String())
		req.SetPermission("authn/oidc_client.view")

		resp, err := handler.CheckMyPermission(ctxAsUser(fixture.member), req)
		if err != nil {
			t.Fatalf("CheckMyPermission: %v", err)
		}
		if !resp.GetAllowed() {
			t.Error("member view permission = false, want true")
		}

		req.SetPermission("authn/oidc_client.manage")
		resp, err = handler.CheckMyPermission(ctxAsUser(fixture.member), req)
		if err != nil {
			t.Fatalf("CheckMyPermission(manage): %v", err)
		}
		if resp.GetAllowed() {
			t.Error("member manage permission = true, want false")
		}
	})

	t.Run("list my permissions", func(t *testing.T) {
		req := &pb.ListMyPermissionsRequest{}
		req.SetOrganizationId(fixture.organizationID.String())

		resp, err := handler.ListMyPermissions(ctxAsUser(fixture.owner), req)
		if err != nil {
			t.Fatalf("ListMyPermissions: %v", err)
		}
		if len(resp.GetPermissions()) == 0 {
			t.Error("owner permissions empty, want the full inherited set")
		}
	})

	t.Run("create my organization makes caller owner", func(t *testing.T) {
		creator := uuid.New()
		req := &pb.CreateMyOrganizationRequest{}
		req.SetName("My New Org")
		req.SetDescription("a freshly created org")

		resp, err := handler.CreateMyOrganization(ctxAsUser(creator), req)
		if err != nil {
			t.Fatalf("CreateMyOrganization: %v", err)
		}
		orgID, err := uuid.Parse(resp.GetOrganizationId())
		if err != nil {
			t.Fatalf("organization id %q is not a uuid", resp.GetOrganizationId())
		}

		// The creator is the owner: org.manage is an owner-only grant.
		allowed, err := fixture.manager.Enforce(ctx, creator, orgID, "authz/org.manage")
		if err != nil {
			t.Fatalf("Enforce: %v", err)
		}
		if !allowed {
			t.Error("creator lacks authz/org.manage, want owner")
		}

		listResp, err := handler.ListMyOrganizations(
			ctxAsUser(creator),
			&pb.ListMyOrganizationsRequest{},
		)
		if err != nil {
			t.Fatalf("ListMyOrganizations: %v", err)
		}
		if len(listResp.GetOrganizations()) != 1 ||
			listResp.GetOrganizations()[0].GetRole() != "owner" {
			t.Errorf(
				"creator memberships = %+v, want one org with role owner",
				listResp.GetOrganizations(),
			)
		}
	})

	t.Run("create my organization without identity is unauthenticated", func(t *testing.T) {
		req := &pb.CreateMyOrganizationRequest{}
		req.SetName("No Caller Org")
		_, err := handler.CreateMyOrganization(context.Background(), req)
		wantCode(t, err, codes.Unauthenticated)
	})
}

func TestAdminHandler(t *testing.T) {
	fixture := newOrgFixture(t, "authzadminhandler")
	handler := NewAdminHandler(HandlerConfig{Manager: fixture.manager})
	ctx := context.Background()

	t.Run("create and delete organization", func(t *testing.T) {
		req := &pb.CreateOrganizationRequest{}
		req.SetName("globex")
		req.SetOwnerUserId(uuid.New().String())

		resp, err := handler.CreateOrganization(ctx, req)
		if err != nil {
			t.Fatalf("CreateOrganization: %v", err)
		}
		orgID := resp.GetOrganizationId()
		if _, err := uuid.Parse(orgID); err != nil {
			t.Fatalf("organization id %q is not a uuid", orgID)
		}

		delReq := &pb.DeleteOrganizationRequest{}
		delReq.SetOrganizationId(orgID)
		if _, err := handler.DeleteOrganization(ctx, delReq); err != nil {
			t.Fatalf("DeleteOrganization: %v", err)
		}
		_, err = handler.DeleteOrganization(ctx, delReq)
		wantCode(t, err, codes.NotFound)
	})

	t.Run("set organization member overrides without owner guard", func(t *testing.T) {
		req := &pb.SetOrganizationMemberRequest{}
		req.SetOrganizationId(fixture.organizationID.String())
		req.SetUserId(fixture.member.String())
		req.SetRole("owner")

		if _, err := handler.SetOrganizationMember(ctx, req); err != nil {
			t.Fatalf("SetOrganizationMember(promote to owner): %v", err)
		}
		allowed, err := fixture.manager.Enforce(
			ctx,
			fixture.member,
			fixture.organizationID,
			"authz/org.manage",
		)
		if err != nil {
			t.Fatalf("Enforce after promotion: %v", err)
		}
		if !allowed {
			t.Error("promoted member org.manage = false, want true")
		}
	})

	t.Run("list rules and reload config", func(t *testing.T) {
		listReq := &pb.ListCasbinRulesRequest{}
		listReq.SetPtype("g")
		listResp, err := handler.ListCasbinRules(ctx, listReq)
		if err != nil {
			t.Fatalf("ListCasbinRules: %v", err)
		}
		if len(listResp.GetRules()) == 0 {
			t.Error("ListCasbinRules(g) returned no rules, want hierarchy + memberships")
		}

		reloadResp, err := handler.ReloadPolicyConfig(ctx, &pb.ReloadPolicyConfigRequest{})
		if err != nil {
			t.Fatalf("ReloadPolicyConfig: %v", err)
		}
		if reloadResp.GetChanged() {
			t.Error("ReloadPolicyConfig changed = true, want false (already reconciled)")
		}
	})

	t.Run("raw policies round trip", func(t *testing.T) {
		rule := &pb.PolicyRule{}
		rule.SetPtype("p")
		rule.SetValues([]string{"role:raw_test", "*", "authz/org", "view"})

		addReq := &pb.AddRawPoliciesRequest{}
		addReq.SetRules([]*pb.PolicyRule{rule})
		if _, err := handler.AddRawPolicies(ctx, addReq); err != nil {
			t.Fatalf("AddRawPolicies: %v", err)
		}

		removeReq := &pb.RemoveRawPoliciesRequest{}
		removeReq.SetRules([]*pb.PolicyRule{rule})
		if _, err := handler.RemoveRawPolicies(ctx, removeReq); err != nil {
			t.Fatalf("RemoveRawPolicies: %v", err)
		}

		bad := &pb.PolicyRule{}
		bad.SetPtype("x")
		bad.SetValues([]string{"only"})
		badReq := &pb.AddRawPoliciesRequest{}
		badReq.SetRules([]*pb.PolicyRule{bad})
		_, err := handler.AddRawPolicies(ctx, badReq)
		wantCode(t, err, codes.InvalidArgument)
		if errors.Is(err, policy.ErrInvalidRule) {
			t.Error("handler leaked the raw sentinel through the status error")
		}
	})
}
