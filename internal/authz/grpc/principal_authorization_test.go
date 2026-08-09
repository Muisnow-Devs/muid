package authzgrpc

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "sanzi.io/muid/api/proto/authz/v1"
	grpcutils "sanzi.io/muid/pkg/grpc_utils"
)

type fakePlatformPermissionChecker struct {
	allowed        bool
	err            error
	gotUserID      uuid.UUID
	gotPermission  string
}

func (f *fakePlatformPermissionChecker) CheckPlatformPermission(
	_ context.Context,
	userID uuid.UUID,
	permission string,
) (bool, error) {
	f.gotUserID = userID
	f.gotPermission = permission
	return f.allowed, f.err
}

func TestAdminAuthorizationInterceptor(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	tests := []struct {
		name           string
		method         string
		withUser       bool
		allowed        bool
		checkerErr     error
		wantPermission string
		wantCode       codes.Code
		wantCalled     bool
	}{
		{
			name:           "organization write allowed",
			method:         pb.AuthzAdminService_CreateOrganization_FullMethodName,
			withUser:       true,
			allowed:        true,
			wantPermission: platformOrganizationWrite,
			wantCode:       codes.OK,
			wantCalled:     true,
		},
		{
			name:           "policy read denied",
			method:         pb.AuthzAdminService_ListCasbinRules_FullMethodName,
			withUser:       true,
			wantPermission: platformPolicyRead,
			wantCode:       codes.PermissionDenied,
		},
		{
			name:           "policy write evaluator failure",
			method:         pb.AuthzAdminService_AddRawPolicies_FullMethodName,
			withUser:       true,
			checkerErr:     errors.New("lookup failed"),
			wantPermission: platformPolicyWrite,
			wantCode:       codes.Internal,
		},
		{
			name:       "missing user",
			method:     pb.AuthzAdminService_ReloadPolicyConfig_FullMethodName,
			wantCode:   codes.Unauthenticated,
		},
		{
			name:       "non-admin bypass",
			method:     pb.AuthzService_CheckOrganizationPermission_FullMethodName,
			wantCode:   codes.OK,
			wantCalled: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			checker := &fakePlatformPermissionChecker{allowed: test.allowed, err: test.checkerErr}
			ctx := context.Background()
			if test.withUser {
				ctx = grpcutils.WithRequestUserID(ctx, userID)
			}
			called := false
			_, err := AdminAuthorizationInterceptor(checker)(
				ctx,
				nil,
				&grpc.UnaryServerInfo{FullMethod: test.method},
				func(context.Context, any) (any, error) {
					called = true
					return nil, nil
				},
			)
			if got := status.Code(err); got != test.wantCode {
				t.Fatalf("status code = %v, want %v", got, test.wantCode)
			}
			if called != test.wantCalled {
				t.Fatalf("handler called = %v, want %v", called, test.wantCalled)
			}
			if test.wantPermission != "" && checker.gotPermission != test.wantPermission {
				t.Fatalf("permission = %q, want %q", checker.gotPermission, test.wantPermission)
			}
			if test.wantPermission != "" && checker.gotUserID != userID {
				t.Fatalf("user id = %v, want %v", checker.gotUserID, userID)
			}
		})
	}
}
