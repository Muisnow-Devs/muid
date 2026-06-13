package authzgrpc

import (
	"context"
	"strings"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "sanzi.io/muid/api/proto/authz/v1"
	"sanzi.io/muid/pkg/audit"
	"sanzi.io/muid/pkg/log"
)

// UserIDMetadataKey is the gRPC metadata key the public gateway sets to the
// verified caller's user id after validating their access/session token.
// Authz never verifies tokens itself, so the public listener must only be
// reachable through the gateway.
const UserIDMetadataKey = "x-user-id"

type userIDContextKey struct{}

// publicServicePrefixes are the full-method prefixes of the RPC surfaces
// that require a gateway-attached user identity.
var publicServicePrefixes = []string{
	"/" + pb.AuthzUserService_ServiceDesc.ServiceName + "/",
	"/" + pb.AuthzOrganizationAdminService_ServiceDesc.ServiceName + "/",
}

// UserIdentityInterceptor extracts the gateway-verified user id from
// request metadata into the context for the public services, rejecting
// requests without one. Other services pass through untouched.
func UserIdentityInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		if !requiresUserIdentity(info.FullMethod) {
			return handler(ctx, req)
		}

		md, _ := metadata.FromIncomingContext(ctx)
		values := md.Get(UserIDMetadataKey)
		if len(values) != 1 {
			return nil, status.Error(codes.Unauthenticated, "user identity required")
		}
		userID, err := uuid.Parse(values[0])
		if err != nil || userID == uuid.Nil {
			return nil, status.Error(codes.Unauthenticated, "user identity required")
		}

		ctx = context.WithValue(ctx, userIDContextKey{}, userID)
		ctx = log.WithAttrs(ctx, log.UserID(userID))
		ctx = audit.WithActor(ctx, userID)
		return handler(ctx, req)
	}
}

func requiresUserIdentity(fullMethod string) bool {
	for _, prefix := range publicServicePrefixes {
		if strings.HasPrefix(fullMethod, prefix) {
			return true
		}
	}
	return false
}

// UserIDFromContext returns the gateway-verified caller id placed by
// UserIdentityInterceptor.
func UserIDFromContext(ctx context.Context) (uuid.UUID, bool) {
	id, ok := ctx.Value(userIDContextKey{}).(uuid.UUID)
	return id, ok
}
