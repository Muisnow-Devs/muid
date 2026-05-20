package profilegrpc

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "sanzi.io/muid/api/proto/profile/v1"
)

func TestProfileRequestContextInterceptor_getProfile(t *testing.T) {
	t.Parallel()

	interceptor := ProfileRequestContextInterceptor()
	id := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
	req := &pb.GetProfileRequest{}
	req.SetId(id.String())

	var got uuid.UUID
	info := &grpc.UnaryServerInfo{FullMethod: pb.ProfileService_GetProfile_FullMethodName}
	_, err := interceptor(
		context.Background(),
		req,
		info,
		func(ctx context.Context, _ any) (any, error) {
			var ok bool
			got, ok = ProfileUserIDFromContext(ctx)
			if !ok {
				t.Fatal("missing profile user id on context")
			}
			return nil, nil
		},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != id {
		t.Fatalf("id: got %v want %v", got, id)
	}
}

func TestProfileRequestContextInterceptor_invalidUserID(t *testing.T) {
	t.Parallel()

	interceptor := ProfileRequestContextInterceptor()
	req := &pb.StartAvatarUploadRequest{}
	req.SetUserId("not-a-uuid")
	req.SetContentType("image/png")

	info := &grpc.UnaryServerInfo{FullMethod: pb.ProfileService_StartAvatarUpload_FullMethodName}
	_, err := interceptor(context.Background(), req, info, func(context.Context, any) (any, error) {
		t.Fatal("handler should not run")
		return nil, nil
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code: got %v", status.Code(err))
	}
	if !strings.Contains(status.Convert(err).Message(), msgInvalidUserID) {
		t.Fatalf("message: %v", status.Convert(err).Message())
	}
}

func TestProfileRequestContextInterceptor_createProfilePassthrough(t *testing.T) {
	t.Parallel()

	interceptor := ProfileRequestContextInterceptor()
	req := &pb.CreateProfileRequest{}
	req.SetEmail("a@example.com")

	info := &grpc.UnaryServerInfo{FullMethod: pb.ProfileService_CreateProfile_FullMethodName}
	called := false
	_, err := interceptor(
		context.Background(),
		req,
		info,
		func(ctx context.Context, _ any) (any, error) {
			called = true
			if _, ok := ProfileUserIDFromContext(ctx); ok {
				t.Fatal("CreateProfile should not set profile user id")
			}
			return nil, nil
		},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Fatal("handler not called")
	}
}
