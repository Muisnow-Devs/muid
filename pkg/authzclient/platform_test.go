package authzclient

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/grpc"

	authzpb "sanzi.io/muid/api/proto/authz/v1"
	"sanzi.io/muid/pkg/shared/authzmodel"
)

func TestNewPlatformChecker(t *testing.T) {
	t.Parallel()

	if _, err := NewPlatformChecker(nil); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("NewPlatformChecker(nil) error = %v, want ErrInvalidConfig", err)
	}
}

func TestPlatformCheckerCheckPermission(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	client := &platformClientStub{allowed: true}
	checker, err := NewPlatformChecker(client)
	if err != nil {
		t.Fatalf("NewPlatformChecker: %v", err)
	}

	allowed, err := checker.CheckPermission(context.Background(), userID, "platform/organization.write")
	if err != nil {
		t.Fatalf("CheckPermission: %v", err)
	}
	if !allowed {
		t.Error("CheckPermission allowed = false, want true")
	}
	if client.userID != userID.String() || client.permission != "platform/organization.write" {
		t.Errorf("request = (%q, %q), want (%q, %q)", client.userID, client.permission, userID, "platform/organization.write")
	}
}

func TestPlatformCheckerCheckPermissionRejectsInvalidInput(t *testing.T) {
	t.Parallel()

	checker, err := NewPlatformChecker(&platformClientStub{})
	if err != nil {
		t.Fatalf("NewPlatformChecker: %v", err)
	}
	if _, err := checker.CheckPermission(context.Background(), uuid.Nil, "platform/organization.write"); err == nil {
		t.Error("CheckPermission accepted nil user ID")
	}
	if _, err := checker.CheckPermission(context.Background(), uuid.New(), "not a permission"); !errors.Is(err, authzmodel.ErrInvalidPermission) {
		t.Errorf("CheckPermission invalid permission error = %v, want ErrInvalidPermission", err)
	}
}

func TestPlatformCheckerCheckPermissionPropagatesTransportError(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("transport failed")
	checker, err := NewPlatformChecker(&platformClientStub{err: wantErr})
	if err != nil {
		t.Fatalf("NewPlatformChecker: %v", err)
	}
	_, err = checker.CheckPermission(context.Background(), uuid.New(), "platform/organization.write")
	if !errors.Is(err, wantErr) {
		t.Errorf("CheckPermission error = %v, want %v", err, wantErr)
	}
}

type platformClientStub struct {
	allowed    bool
	err        error
	userID     string
	permission string
}

func (c *platformClientStub) CheckOrganizationMembership(context.Context, *authzpb.CheckOrganizationMembershipRequest, ...grpc.CallOption) (*authzpb.CheckOrganizationMembershipResponse, error) {
	panic("not used")
}

func (c *platformClientStub) CheckOrganizationPermission(context.Context, *authzpb.CheckOrganizationPermissionRequest, ...grpc.CallOption) (*authzpb.CheckOrganizationPermissionResponse, error) {
	panic("not used")
}

func (c *platformClientStub) CheckPlatformPermission(_ context.Context, req *authzpb.CheckPlatformPermissionRequest, _ ...grpc.CallOption) (*authzpb.CheckPlatformPermissionResponse, error) {
	c.userID = req.GetUserId()
	c.permission = req.GetPermission()
	if c.err != nil {
		return nil, c.err
	}
	resp := &authzpb.CheckPlatformPermissionResponse{}
	resp.SetAllowed(c.allowed)
	return resp, nil
}

func (c *platformClientStub) ListNamespacePolicies(context.Context, *authzpb.ListNamespacePoliciesRequest, ...grpc.CallOption) (*authzpb.ListNamespacePoliciesResponse, error) {
	panic("not used")
}

func (c *platformClientStub) ListUserOrganizationRoles(context.Context, *authzpb.ListUserOrganizationRolesRequest, ...grpc.CallOption) (*authzpb.ListUserOrganizationRolesResponse, error) {
	panic("not used")
}
