package authngrpc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "sanzi.io/muid/api/proto/authn/v1"
	grpcutils "sanzi.io/muid/pkg/grpc_utils"
	"sanzi.io/muid/pkg/shared/authzmodel"
)

type fakePlatformPermissionChecker struct {
	allowed    bool
	err        error
	userID     uuid.UUID
	permission string
}

func (f *fakePlatformPermissionChecker) CheckPermission(
	_ context.Context,
	userID uuid.UUID,
	permission string,
) (bool, error) {
	f.userID = userID
	f.permission = permission
	return f.allowed, f.err
}

func TestOIDCAdminPlatformPermissionMapping(t *testing.T) {
	t.Parallel()

	tests := []struct {
		method     string
		permission string
	}{
		{pb.OIDCClientAdminService_GetOIDCClient_FullMethodName, authzmodel.PlatformPermissionOIDCClientRead},
		{pb.OIDCClientAdminService_ListOIDCClients_FullMethodName, authzmodel.PlatformPermissionOIDCClientRead},
		{pb.OIDCClientAdminService_ListOIDCClientSecrets_FullMethodName, authzmodel.PlatformPermissionOIDCClientRead},
		{pb.OIDCClientAdminService_ListOIDCClientAccessGrants_FullMethodName, authzmodel.PlatformPermissionOIDCClientRead},
		{pb.OIDCClientAdminService_CreateOIDCClient_FullMethodName, authzmodel.PlatformPermissionOIDCClientWrite},
		{pb.OIDCClientAdminService_UpdateOIDCClient_FullMethodName, authzmodel.PlatformPermissionOIDCClientWrite},
		{pb.OIDCClientAdminService_SetOIDCClientPublishStatus_FullMethodName, authzmodel.PlatformPermissionOIDCClientWrite},
		{pb.OIDCClientAdminService_AddOIDCClientRedirectURI_FullMethodName, authzmodel.PlatformPermissionOIDCClientWrite},
		{pb.OIDCClientAdminService_RemoveOIDCClientRedirectURI_FullMethodName, authzmodel.PlatformPermissionOIDCClientWrite},
		{pb.OIDCClientAdminService_CreateOIDCClientSecret_FullMethodName, authzmodel.PlatformPermissionOIDCClientWrite},
		{pb.OIDCClientAdminService_RevokeOIDCClientSecret_FullMethodName, authzmodel.PlatformPermissionOIDCClientWrite},
		{pb.OIDCClientAdminService_AddOIDCClientAccessGrant_FullMethodName, authzmodel.PlatformPermissionOIDCClientWrite},
		{pb.OIDCClientAdminService_RemoveOIDCClientAccessGrant_FullMethodName, authzmodel.PlatformPermissionOIDCClientWrite},
	}

	for _, test := range tests {
		permission, ok := oidcAdminPlatformPermission(test.method)
		if !ok || permission != test.permission {
			t.Errorf("permission for %q = (%q, %v), want (%q, true)", test.method, permission, ok, test.permission)
		}
	}
	if len(tests) != len(pb.OIDCClientAdminService_ServiceDesc.Methods) {
		t.Fatalf("mapped methods = %d, service methods = %d", len(tests), len(pb.OIDCClientAdminService_ServiceDesc.Methods))
	}
}

func TestOIDCAdminPlatformAuthorizationInterceptor(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	tests := []struct {
		name       string
		checker    *fakePlatformPermissionChecker
		withUser   bool
		method     string
		wantCode   codes.Code
		wantCalled bool
		permission string
	}{
		{
			name:       "allowed read",
			checker:    &fakePlatformPermissionChecker{allowed: true},
			withUser:   true,
			method:     pb.OIDCClientAdminService_ListOIDCClients_FullMethodName,
			wantCode:   codes.OK,
			wantCalled: true,
			permission: authzmodel.PlatformPermissionOIDCClientRead,
		},
		{
			name:       "denied",
			checker:    &fakePlatformPermissionChecker{},
			withUser:   true,
			method:     pb.OIDCClientAdminService_CreateOIDCClient_FullMethodName,
			wantCode:   codes.PermissionDenied,
			wantCalled: false,
		},
		{
			name:       "authorization unavailable",
			checker:    &fakePlatformPermissionChecker{err: errors.New("backend down")},
			withUser:   true,
			method:     pb.OIDCClientAdminService_CreateOIDCClient_FullMethodName,
			wantCode:   codes.Unavailable,
			wantCalled: false,
		},
		{
			name:       "missing user",
			checker:    &fakePlatformPermissionChecker{allowed: true},
			method:     pb.OIDCClientAdminService_CreateOIDCClient_FullMethodName,
			wantCode:   codes.Unauthenticated,
			wantCalled: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			if test.withUser {
				ctx = grpcutils.WithRequestUserID(ctx, userID)
			}
			called := false
			_, err := OIDCAdminPlatformAuthorizationInterceptor(test.checker)(
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
			if test.permission != "" {
				if test.checker.userID != userID || test.checker.permission != test.permission {
					t.Fatalf("check = (%v, %q), want (%v, %q)", test.checker.userID, test.checker.permission, userID, test.permission)
				}
			}
		})
	}
}

func TestOIDCAdminPlatformAuthorizationInterceptorFailsClosedWithoutChecker(t *testing.T) {
	t.Parallel()

	ctx := grpcutils.WithRequestUserID(context.Background(), uuid.New())
	called := false
	_, err := OIDCAdminPlatformAuthorizationInterceptor(nil)(
		ctx,
		nil,
		&grpc.UnaryServerInfo{FullMethod: pb.OIDCClientAdminService_ListOIDCClients_FullMethodName},
		func(context.Context, any) (any, error) {
			called = true
			return nil, nil
		},
	)
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("status code = %v, want Unavailable", status.Code(err))
	}
	if called {
		t.Fatal("handler ran without a platform authorization client")
	}
}

func TestOIDCAdminPlatformAuthorizationInterceptorBypassesNonAdminMethod(t *testing.T) {
	t.Parallel()

	called := false
	_, err := OIDCAdminPlatformAuthorizationInterceptor(nil)(
		context.Background(),
		nil,
		&grpc.UnaryServerInfo{FullMethod: pb.SigningKeyService_GetPublicKeys_FullMethodName},
		func(context.Context, any) (any, error) {
			called = true
			return nil, nil
		},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Fatal("non-admin handler was not called")
	}
}

func TestOIDCAdminPlatformAuthorizationInterceptorRejectsUnknownAdminMethod(t *testing.T) {
	t.Parallel()

	called := false
	_, err := OIDCAdminPlatformAuthorizationInterceptor(&fakePlatformPermissionChecker{allowed: true})(
		grpcutils.WithRequestUserID(context.Background(), uuid.New()),
		nil,
		&grpc.UnaryServerInfo{FullMethod: "/" + pb.OIDCClientAdminService_ServiceDesc.ServiceName + "/FutureMutation"},
		func(context.Context, any) (any, error) {
			called = true
			return nil, nil
		},
	)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("status code = %v, want PermissionDenied", status.Code(err))
	}
	if called {
		t.Fatal("unknown admin handler ran without a permission mapping")
	}
}

type deadlinePlatformChecker struct {
	sawDeadline bool
}

func (c *deadlinePlatformChecker) CheckPermission(
	ctx context.Context,
	_ uuid.UUID,
	_ string,
) (bool, error) {
	_, c.sawDeadline = ctx.Deadline()
	<-ctx.Done()
	return false, ctx.Err()
}

func TestOIDCAdminPlatformAuthorizationInterceptorPropagatesDeadline(t *testing.T) {
	t.Parallel()

	checker := &deadlinePlatformChecker{}
	ctx, cancel := context.WithTimeout(
		grpcutils.WithRequestUserID(context.Background(), uuid.New()),
		50*time.Millisecond,
	)
	defer cancel()

	_, err := OIDCAdminPlatformAuthorizationInterceptor(checker)(
		ctx,
		nil,
		&grpc.UnaryServerInfo{FullMethod: pb.OIDCClientAdminService_ListOIDCClients_FullMethodName},
		func(context.Context, any) (any, error) {
			t.Fatal("handler ran after the authorization deadline")
			return nil, nil
		},
	)
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("status code = %v, want Unavailable", status.Code(err))
	}
	if !checker.sawDeadline {
		t.Fatal("authorization checker did not receive the request deadline")
	}
}
