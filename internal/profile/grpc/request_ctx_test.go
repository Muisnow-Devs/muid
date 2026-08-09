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

func TestCurrentProfileRequestContextInterceptorAcceptsUnauthenticatedUserIDMetadata(t *testing.T) {
	t.Parallel()

	forgedUserID := uuid.MustParse("4c29a0d6-91b4-4a4f-8c39-6f3dd35a57ea")
	ctx := metadata.NewIncomingContext(
		context.Background(),
		metadata.Pairs(sharedauthn.AuthenticatedUserIDMetadataKey, forgedUserID.String()),
	)
	req := &pb.GetProfileRequest{}

	var gotUserID uuid.UUID
	_, err := ProfileRequestContextInterceptor()(
		ctx,
		req,
		&grpc.UnaryServerInfo{FullMethod: pb.ProfileService_GetProfile_FullMethodName},
		func(ctx context.Context, _ any) (any, error) {
			var ok bool
			gotUserID, ok = sharedauthn.AuthenticatedUserIDFromContext(ctx)
			if !ok {
				t.Fatal("handler did not receive the metadata identity")
			}
			return nil, nil
		},
	)
	if err != nil {
		t.Fatalf("interceptor error = %v, want nil", err)
	}
	if gotUserID != forgedUserID {
		t.Fatalf("handler user id = %v, want forged metadata id %v", gotUserID, forgedUserID)
	}
}

func TestProfileRequestContextInterceptor_preservesLegacyPrincipalParsing(t *testing.T) {
	t.Parallel()

	interceptor := ProfileRequestContextInterceptor()
	metadataID := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
	secondMetadataID := uuid.MustParse("e1e7e564-9102-4c94-815c-eaaf2c4da7b2")
	requestID := uuid.MustParse("f80f6e2c-5928-4ea3-9a80-d01156130141")

	t.Run("first trimmed metadata value is used when request id is empty", func(t *testing.T) {
		ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
			sharedauthn.AuthenticatedUserIDMetadataKey, " "+metadataID.String()+" ",
			sharedauthn.AuthenticatedUserIDMetadataKey, secondMetadataID.String(),
		))
		req := &pb.GetProfileRequest{}

		_, err := interceptor(ctx, req, &grpc.UnaryServerInfo{
			FullMethod: pb.ProfileService_GetProfile_FullMethodName,
		}, func(ctx context.Context, _ any) (any, error) {
			got, ok := sharedauthn.AuthenticatedUserIDFromContext(ctx)
			if !ok || got != metadataID {
				t.Errorf("authenticated user = (%v, %v), want (%v, true)", got, ok, metadataID)
			}
			return nil, nil
		})
		if err != nil {
			t.Fatalf("interceptor error = %v", err)
		}
	})

	t.Run("trimmed request id overrides metadata", func(t *testing.T) {
		ctx := metadata.NewIncomingContext(
			context.Background(),
			metadata.Pairs(sharedauthn.AuthenticatedUserIDMetadataKey, metadataID.String()),
		)
		req := &pb.GetProfileRequest{}
		req.SetId(" \t" + requestID.String() + "\n")

		_, err := interceptor(ctx, req, &grpc.UnaryServerInfo{
			FullMethod: pb.ProfileService_GetProfile_FullMethodName,
		}, func(ctx context.Context, _ any) (any, error) {
			got, ok := sharedauthn.AuthenticatedUserIDFromContext(ctx)
			if !ok || got != requestID {
				t.Errorf("authenticated user = (%v, %v), want (%v, true)", got, ok, requestID)
			}
			return nil, nil
		})
		if err != nil {
			t.Fatalf("interceptor error = %v", err)
		}
	})
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

func TestProfileRequestContextInterceptor_updateOrganizationProfileRequiresPrincipal(t *testing.T) {
	t.Parallel()

	interceptor := ProfileRequestContextInterceptor()
	req := &pb.UpdateOrganizationProfileRequest{}
	info := &grpc.UnaryServerInfo{
		FullMethod: pb.OrganizationProfileService_UpdateOrganizationProfile_FullMethodName,
	}

	called := false
	_, err := interceptor(
		context.Background(), // no x-authn-user-id metadata
		req,
		info,
		func(context.Context, any) (any, error) {
			called = true
			return nil, nil
		},
	)
	if err == nil {
		t.Fatal("expected error for missing authenticated principal")
	}
	if called {
		t.Fatal("handler should not run without an authenticated principal")
	}
}

func TestProfileRequestContextInterceptor_createOrganizationProfilePassthrough(t *testing.T) {
	t.Parallel()

	interceptor := ProfileRequestContextInterceptor()
	req := &pb.CreateOrganizationProfileRequest{}
	info := &grpc.UnaryServerInfo{
		FullMethod: pb.OrganizationProfileService_CreateOrganizationProfile_FullMethodName,
	}

	called := false
	_, err := interceptor(
		context.Background(),
		req,
		info,
		func(ctx context.Context, _ any) (any, error) {
			called = true
			if _, ok := sharedauthn.AuthenticatedUserIDFromContext(ctx); ok {
				t.Fatal("CreateOrganizationProfile should not require a principal")
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
