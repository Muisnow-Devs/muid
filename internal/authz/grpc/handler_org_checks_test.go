package authzgrpc

import (
	"context"
	"testing"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"

	pb "sanzi.io/muid/api/proto/authz/v1"
	authzent "sanzi.io/muid/internal/authz/ent"
	"sanzi.io/muid/internal/authz/ent/enttest"
)

type orgFixture struct {
	organizationID uuid.UUID
	memberWithPerm uuid.UUID
	memberNoPerm   uuid.UUID
	nonMember      uuid.UUID
}

func newOrgFixture(t *testing.T, client *authzent.Client) orgFixture {
	t.Helper()
	ctx := context.Background()

	fixture := orgFixture{
		memberWithPerm: uuid.New(),
		memberNoPerm:   uuid.New(),
		nonMember:      uuid.New(),
	}

	org, err := client.Organization.Create().
		SetName("Acme").
		SetDomain("acme.test").
		Save(ctx)
	if err != nil {
		t.Fatalf("create organization: %v", err)
	}
	fixture.organizationID = org.ID

	adminRole, err := client.OrganizationRole.Create().
		SetOrganizationID(org.ID).
		SetName("admin").
		Save(ctx)
	if err != nil {
		t.Fatalf("create admin role: %v", err)
	}
	memberRole, err := client.OrganizationRole.Create().
		SetOrganizationID(org.ID).
		SetName("member").
		Save(ctx)
	if err != nil {
		t.Fatalf("create member role: %v", err)
	}

	err = client.RolePermission.Create().
		SetRoleID(adminRole.ID).
		SetPermission("oidc_client:manage").
		Exec(ctx)
	if err != nil {
		t.Fatalf("create role permission: %v", err)
	}

	for userID, roleID := range map[uuid.UUID]uuid.UUID{
		fixture.memberWithPerm: adminRole.ID,
		fixture.memberNoPerm:   memberRole.ID,
	} {
		err = client.UserRef.Create().SetID(userID).Exec(ctx)
		if err != nil {
			t.Fatalf("create user ref: %v", err)
		}
		err = client.OrganizationMember.Create().
			SetOrganizationID(org.ID).
			SetUserID(userID).
			SetRoleID(roleID).
			Exec(ctx)
		if err != nil {
			t.Fatalf("create membership: %v", err)
		}
	}

	return fixture
}

func TestCheckOrganizationMembership(t *testing.T) {
	t.Parallel()

	client := enttest.Open(t, "sqlite3", "file:authzmembership?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() { client.Close() })
	fixture := newOrgFixture(t, client)
	handler := NewGRPCHandler(HandlerConfig{DB: client})

	tests := []struct {
		name   string
		userID uuid.UUID
		want   bool
	}{
		{name: "member", userID: fixture.memberNoPerm, want: true},
		{name: "non-member", userID: fixture.nonMember, want: false},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

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
	t.Parallel()

	client := enttest.Open(t, "sqlite3", "file:authzpermission?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() { client.Close() })
	fixture := newOrgFixture(t, client)
	handler := NewGRPCHandler(HandlerConfig{DB: client})

	tests := []struct {
		name        string
		userID      uuid.UUID
		permission  string
		wantAllowed bool
		wantMember  bool
	}{
		{
			name:        "member with permission",
			userID:      fixture.memberWithPerm,
			permission:  "oidc_client:manage",
			wantAllowed: true,
			wantMember:  true,
		},
		{
			name:       "member without permission",
			userID:     fixture.memberNoPerm,
			permission: "oidc_client:manage",
			wantMember: true,
		},
		{
			name:       "member with unknown permission",
			userID:     fixture.memberWithPerm,
			permission: "organization:delete",
			wantMember: true,
		},
		{
			name:       "non-member",
			userID:     fixture.nonMember,
			permission: "oidc_client:manage",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

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
