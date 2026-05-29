package profilegrpc

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	pb "sanzi.io/muid/api/proto/profile/v1"
	sharedauthn "sanzi.io/muid/pkg/shared/authn"
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
			got, ok = sharedauthn.AuthenticatedUserIDFromContext(ctx)
			if !ok {
				t.Fatal("missing authenticated user id on context")
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

func TestProfileRequestContextInterceptor_getProfileDefaultsToAuthenticatedUser(t *testing.T) {
	t.Parallel()

	interceptor := ProfileRequestContextInterceptor()
	id := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
	req := &pb.GetProfileRequest{}
	ctx := metadata.NewIncomingContext(
		context.Background(),
		metadata.Pairs(sharedauthn.AuthenticatedUserIDMetadataKey, id.String()),
	)

	var got uuid.UUID
	info := &grpc.UnaryServerInfo{FullMethod: pb.ProfileService_GetProfile_FullMethodName}
	_, err := interceptor(
		ctx,
		req,
		info,
		func(ctx context.Context, _ any) (any, error) {
			var ok bool
			got, ok = sharedauthn.AuthenticatedUserIDFromContext(ctx)
			if !ok {
				t.Fatal("missing authenticated user id on context")
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

func TestProfileRequestContextInterceptor_updateProfile(t *testing.T) {
	t.Parallel()

	interceptor := ProfileRequestContextInterceptor()
	id := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
	req := &pb.UpdateProfileRequest{}
	ctx := metadata.NewIncomingContext(
		context.Background(),
		metadata.Pairs(sharedauthn.AuthenticatedUserIDMetadataKey, id.String()),
	)

	var got uuid.UUID
	info := &grpc.UnaryServerInfo{FullMethod: pb.ProfileService_UpdateProfile_FullMethodName}
	_, err := interceptor(
		ctx,
		req,
		info,
		func(ctx context.Context, _ any) (any, error) {
			var ok bool
			got, ok = sharedauthn.AuthenticatedUserIDFromContext(ctx)
			if !ok {
				t.Fatal("missing authenticated user id on context")
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

func TestProfileRequestContextInterceptor_createProfilePassthrough(t *testing.T) {
	t.Parallel()

	interceptor := ProfileRequestContextInterceptor()
	req := &pb.CreateProfileRequest{}

	info := &grpc.UnaryServerInfo{FullMethod: pb.ProfileService_CreateProfile_FullMethodName}
	called := false
	_, err := interceptor(
		context.Background(),
		req,
		info,
		func(ctx context.Context, _ any) (any, error) {
			called = true
			if _, ok := sharedauthn.AuthenticatedUserIDFromContext(ctx); ok {
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
