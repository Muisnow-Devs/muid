package authzgrpc

import (
	"context"
	"testing"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"

	pb "sanzi.io/muid/api/proto/authz/v1"
	"sanzi.io/muid/internal/authz/ent/enttest"
	"sanzi.io/muid/internal/authz/policy"
)

type orgFixture struct {
	manager        *policy.Manager
	organizationID uuid.UUID
	owner          uuid.UUID
	admin          uuid.UUID
	member         uuid.UUID
	nonMember      uuid.UUID
}

// newOrgFixture builds a manager on in-memory sqlite with the default
// static policy, one organization, and members in the admin/member system
// roles.
func newOrgFixture(t *testing.T, dbName string) orgFixture {
	t.Helper()
	ctx := context.Background()

	client := enttest.Open(t, "sqlite3", "file:"+dbName+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() { client.Close() })

	cfg, err := policy.LoadStaticConfig("", "")
	if err != nil {
		t.Fatalf("LoadStaticConfig: %v", err)
	}
	manager, err := policy.NewManager(policy.ManagerConfig{DB: client, Config: cfg})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(func() { manager.Close() })
	if _, _, err := manager.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	fixture := orgFixture{
		manager:   manager,
		owner:     uuid.New(),
		admin:     uuid.New(),
		member:    uuid.New(),
		nonMember: uuid.New(),
	}
	fixture.organizationID, err = manager.CreateOrganization(
		ctx,
		"Acme",
		"",
		fixture.owner,
	)
	if err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}
	if err := manager.AddMember(ctx, fixture.owner, fixture.organizationID, fixture.admin, "admin"); err != nil {
		t.Fatalf("AddMember(admin): %v", err)
	}
	if err := manager.AddMember(ctx, fixture.owner, fixture.organizationID, fixture.member, "member"); err != nil {
		t.Fatalf("AddMember(member): %v", err)
	}
	return fixture
}

func TestCheckOrganizationMembership(t *testing.T) {
	fixture := newOrgFixture(t, "authzmembership")
	handler := NewGRPCHandler(HandlerConfig{Manager: fixture.manager})

	tests := []struct {
		name   string
		userID uuid.UUID
		want   bool
	}{
		{name: "member", userID: fixture.member, want: true},
		{name: "non-member", userID: fixture.nonMember, want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := &pb.CheckOrganizationMembershipRequest{}
			req.SetOrganizationId(fixture.organizationID.String())
			req.SetUserId(tc.userID.String())

			resp, err := handler.CheckOrganizationMembership(context.Background(), req)
			if err != nil {
				t.Fatalf("CheckOrganizationMembership: %v", err)
			}
			if resp.GetIsMember() != tc.want {
				t.Fatalf("is_member = %v, want %v", resp.GetIsMember(), tc.want)
			}
		})
	}
}

func TestCheckOrganizationPermission(t *testing.T) {
	fixture := newOrgFixture(t, "authzpermission")
	handler := NewGRPCHandler(HandlerConfig{Manager: fixture.manager})

	tests := []struct {
		name        string
		userID      uuid.UUID
		permission  string
		wantAllowed bool
		wantMember  bool
	}{
		{
			name:        "admin holds the manage grant",
			userID:      fixture.admin,
			permission:  "authn/oidc_client.manage",
			wantAllowed: true,
			wantMember:  true,
		},
		{
			name:        "owner inherits the manage grant",
			userID:      fixture.owner,
			permission:  "authn/oidc_client.manage",
			wantAllowed: true,
			wantMember:  true,
		},
		{
			name:       "member lacks the manage grant",
			userID:     fixture.member,
			permission: "authn/oidc_client.manage",
			wantMember: true,
		},
		{
			name:        "member holds the view grant",
			userID:      fixture.member,
			permission:  "authn/oidc_client.view",
			wantAllowed: true,
			wantMember:  true,
		},
		{
			name:       "non-member",
			userID:     fixture.nonMember,
			permission: "authn/oidc_client.manage",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := &pb.CheckOrganizationPermissionRequest{}
			req.SetOrganizationId(fixture.organizationID.String())
			req.SetUserId(tc.userID.String())
			req.SetPermission(tc.permission)

			resp, err := handler.CheckOrganizationPermission(context.Background(), req)
			if err != nil {
				t.Fatalf("CheckOrganizationPermission: %v", err)
			}
			if resp.GetAllowed() != tc.wantAllowed || resp.GetIsMember() != tc.wantMember {
				t.Fatalf(
					"result = (allowed %v, member %v), want (allowed %v, member %v)",
					resp.GetAllowed(), resp.GetIsMember(), tc.wantAllowed, tc.wantMember,
				)
			}
		})
	}
}

func TestListUserOrganizationRoles(t *testing.T) {
	fixture := newOrgFixture(t, "authzuserroles")
	handler := NewGRPCHandler(HandlerConfig{Manager: fixture.manager})

	req := &pb.ListUserOrganizationRolesRequest{}
	req.SetOrganizationId(fixture.organizationID.String())
	req.SetUserId(fixture.admin.String())

	resp, err := handler.ListUserOrganizationRoles(context.Background(), req)
	if err != nil {
		t.Fatalf("ListUserOrganizationRoles: %v", err)
	}
	if !resp.GetIsMember() || len(resp.GetRoles()) != 1 || resp.GetRoles()[0] != "admin" {
		t.Fatalf("roles = %v (member %v), want [admin] (member true)",
			resp.GetRoles(), resp.GetIsMember())
	}
}

func TestListNamespacePolicies(t *testing.T) {
	fixture := newOrgFixture(t, "authznamespacepolicies")
	handler := NewGRPCHandler(HandlerConfig{Manager: fixture.manager})

	req := &pb.ListNamespacePoliciesRequest{}
	req.SetNamespace("authn")

	resp, err := handler.ListNamespacePolicies(context.Background(), req)
	if err != nil {
		t.Fatalf("ListNamespacePolicies: %v", err)
	}
	if len(resp.GetRules()) == 0 {
		t.Fatal("ListNamespacePolicies returned no rules, want authn grants + hierarchy")
	}
	if resp.GetRevisionId() == "" {
		t.Error("revision_id is empty, want a snapshot id")
	}
	for _, rule := range resp.GetRules() {
		switch rule.GetPtype() {
		case "p", "g":
		default:
			t.Errorf("unexpected ptype %q in rule %v", rule.GetPtype(), rule.GetValues())
		}
	}
}
