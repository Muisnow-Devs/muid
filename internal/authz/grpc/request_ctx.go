package authzgrpc

import (
	"context"

	"google.golang.org/grpc"

	pb "sanzi.io/muid/api/proto/authz/v1"
	grpcutils "sanzi.io/muid/pkg/grpc_utils"
	sharedauthn "sanzi.io/muid/pkg/shared/authn"
)

// AuthzRequestContextInterceptor validates authenticated principals from gRPC metadata.
func AuthzRequestContextInterceptor() grpc.UnaryServerInterceptor {
	return grpcutils.UnaryRequestContextInterceptor(map[string]grpcutils.RequestContextFunc{
		pb.AuthzService_OIDCGrantConsent_FullMethodName:        enrichRequiredPrincipal,
		pb.AuthzService_OIDCRevokeConsent_FullMethodName:       enrichRequiredPrincipal,
		pb.AuthzService_OIDCListGrantedConsents_FullMethodName: enrichRequiredPrincipal,
	})
}

func enrichRequiredPrincipal(ctx context.Context, _ string, _ any) (context.Context, error) {
	ctx, _, err := sharedauthn.EnrichRequiredAuthenticatedUser(ctx)
	return ctx, err
}
