package authzmodel

import (
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestSplitPermission(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		permission string
		wantObj    string
		wantAct    string
		wantErr    error
	}{
		{
			name:       "simple",
			permission: "authn/oidc_client.manage",
			wantObj:    "authn/oidc_client",
			wantAct:    "manage",
		},
		{
			name:       "underscores and digits",
			permission: "authz/member_v2.view",
			wantObj:    "authz/member_v2",
			wantAct:    "view",
		},
		{
			name:       "empty",
			permission: "",
			wantErr:    ErrInvalidPermission,
		},
		{
			name:       "oidc scope style colon",
			permission: "authn:oidc_client.manage",
			wantErr:    ErrInvalidPermission,
		},
		{
			name:       "missing action",
			permission: "authn/oidc_client",
			wantErr:    ErrInvalidPermission,
		},
		{
			name:       "missing namespace",
			permission: "oidc_client.manage",
			wantErr:    ErrInvalidPermission,
		},
		{
			name:       "uppercase",
			permission: "Authn/Client.Manage",
			wantErr:    ErrInvalidPermission,
		},
		{
			name:       "extra segment",
			permission: "authn/oidc_client.manage.all",
			wantErr:    ErrInvalidPermission,
		},
		{
			name:       "leading digit namespace",
			permission: "1authn/oidc_client.manage",
			wantErr:    ErrInvalidPermission,
		},
		{
			name:       "double slash",
			permission: "authn/oidc/client.manage",
			wantErr:    ErrInvalidPermission,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			obj, act, err := SplitPermission(tt.permission)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("SplitPermission(%q) error = %v, want %v", tt.permission, err, tt.wantErr)
			}
			if obj != tt.wantObj || act != tt.wantAct {
				t.Errorf("SplitPermission(%q) = (%q, %q), want (%q, %q)",
					tt.permission, obj, act, tt.wantObj, tt.wantAct)
			}
			if tt.wantErr == nil && JoinPermission(obj, act) != tt.permission {
				t.Errorf("JoinPermission(%q, %q) = %q, want %q",
					obj, act, JoinPermission(obj, act), tt.permission)
			}
		})
	}
}

func TestNamespace(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		permission string
		want       string
		wantErr    error
	}{
		{name: "authn", permission: "authn/oidc_client.manage", want: "authn"},
		{name: "authz", permission: "authz/member.view", want: "authz"},
		{name: "invalid", permission: "not-a-permission", wantErr: ErrInvalidPermission},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := Namespace(tt.permission)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Namespace(%q) error = %v, want %v", tt.permission, err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("Namespace(%q) = %q, want %q", tt.permission, got, tt.want)
			}
		})
	}
}

func TestSubjects(t *testing.T) {
	t.Parallel()

	id := uuid.MustParse("0195a000-0000-7000-8000-000000000001")
	if got, want := UserSubject(id), "user:"+id.String(); got != want {
		t.Errorf("UserSubject(%v) = %q, want %q", id, got, want)
	}
	if got, want := RoleSubject("owner"), "role:owner"; got != want {
		t.Errorf("RoleSubject(owner) = %q, want %q", got, want)
	}

	name, ok := RoleName("role:admin")
	if !ok || name != "admin" {
		t.Errorf("RoleName(role:admin) = (%q, %v), want (admin, true)", name, ok)
	}
	if _, ok := RoleName("user:abc"); ok {
		t.Error("RoleName(user:abc) ok = true, want false")
	}
	if _, ok := RoleName("role:"); ok {
		t.Error("RoleName(role:) ok = true, want false")
	}
}
