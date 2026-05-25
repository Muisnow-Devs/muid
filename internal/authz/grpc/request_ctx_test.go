package authzgrpc

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "sanzi.io/muid/api/proto/authz/v1"
	sharedauthn "sanzi.io/muid/pkg/shared/authn"
)

func TestAuthzRequestContextInterceptor_requiredPrincipal(t *testing.T) {
	t.Parallel()

	interceptor := AuthzRequestContextInterceptor()
	id := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
	ctx := metadata.NewIncomingContext(
		context.Background(),
		metadata.Pairs(sharedauthn.AuthenticatedUserIDMetadataKey, id.String()),
	)

	var got uuid.UUID
	info := &grpc.UnaryServerInfo{FullMethod: pb.AuthzService_OIDCGrantConsent_FullMethodName}
	_, err := interceptor(
		ctx,
		&pb.OIDCGrantConsentRequest{},
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
		t.Fatalf("user id: got %v want %v", got, id)
	}
}

func TestAuthzRequestContextInterceptor_missingPrincipal(t *testing.T) {
	t.Parallel()

	interceptor := AuthzRequestContextInterceptor()
	info := &grpc.UnaryServerInfo{FullMethod: pb.AuthzService_OIDCRevokeConsent_FullMethodName}
	_, err := interceptor(
		context.Background(),
		&pb.OIDCRevokeConsentRequest{},
		info,
		func(context.Context, any) (any, error) {
			t.Fatal("handler should not run")
			return nil, nil
		},
	)
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code: got %v", status.Code(err))
	}
	if status.Convert(err).Message() != sharedauthn.MsgMissingAuthenticatedPrincipal {
		t.Fatalf("message: %v", status.Convert(err).Message())
	}
}

func TestAuthzRequestContextInterceptor_invalidPrincipal(t *testing.T) {
	t.Parallel()

	interceptor := AuthzRequestContextInterceptor()
	ctx := metadata.NewIncomingContext(
		context.Background(),
		metadata.Pairs(sharedauthn.AuthenticatedUserIDMetadataKey, "not-a-uuid"),
	)
	info := &grpc.UnaryServerInfo{
		FullMethod: pb.AuthzService_OIDCListGrantedConsents_FullMethodName,
	}
	_, err := interceptor(
		ctx,
		&pb.OIDCListGrantedConsentsRequest{},
		info,
		func(context.Context, any) (any, error) {
			t.Fatal("handler should not run")
			return nil, nil
		},
	)
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code: got %v", status.Code(err))
	}
	if status.Convert(err).Message() != sharedauthn.MsgInvalidAuthenticatedPrincipal {
		t.Fatalf("message: %v", status.Convert(err).Message())
	}
}
