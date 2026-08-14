package authngrpc

import (
	"context"
	"strings"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "sanzi.io/muid/api/proto/authn/v1"
	grpcutils "sanzi.io/muid/pkg/grpc_utils"
	"sanzi.io/muid/pkg/log"
	"sanzi.io/muid/pkg/shared/authzmodel"
)

type platformPermissionChecker interface {
	CheckPermission(context.Context, uuid.UUID, string) (bool, error)
}

// OIDCAdminPlatformAuthorizationInterceptor enforces live platform authority
// before the OIDC domain layer performs its existing organization check.
func OIDCAdminPlatformAuthorizationInterceptor(
	checker platformPermissionChecker,
) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		permission, adminMethod := oidcAdminPlatformPermission(info.FullMethod)
		if !adminMethod {
			adminPrefix := "/" + pb.OIDCClientAdminService_ServiceDesc.ServiceName + "/"
			if strings.HasPrefix(info.FullMethod, adminPrefix) {
				return nil, status.Error(codes.PermissionDenied, "method not permitted")
			}
			return handler(ctx, req)
		}
		if checker == nil {
			return nil, status.Error(codes.Unavailable, "authorization unavailable")
		}
		userID, ok := grpcutils.RequestUserIDFromContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "user identity required")
		}
		ctx = log.WithAttrs(ctx, log.UserID(userID))
		allowed, err := checker.CheckPermission(ctx, userID, permission)
		if err != nil {
			log.LogUnexpected(ctx, "oidc admin platform permission", err.Error())
			return nil, status.Error(codes.Unavailable, "authorization unavailable")
		}
		if !allowed {
			return nil, status.Error(codes.PermissionDenied, "permission denied")
		}
		return handler(ctx, req)
	}
}

func oidcAdminPlatformPermission(fullMethod string) (string, bool) {
	switch fullMethod {
	case pb.OIDCClientAdminService_GetOIDCClient_FullMethodName,
		pb.OIDCClientAdminService_ListOIDCClients_FullMethodName,
		pb.OIDCClientAdminService_ListOIDCClientSecrets_FullMethodName,
		pb.OIDCClientAdminService_ListOIDCClientAccessGrants_FullMethodName:
		return authzmodel.PlatformPermissionOIDCClientRead, true
	case pb.OIDCClientAdminService_CreateOIDCClient_FullMethodName,
		pb.OIDCClientAdminService_UpdateOIDCClient_FullMethodName,
		pb.OIDCClientAdminService_SetOIDCClientPublishStatus_FullMethodName,
		pb.OIDCClientAdminService_AddOIDCClientRedirectURI_FullMethodName,
		pb.OIDCClientAdminService_RemoveOIDCClientRedirectURI_FullMethodName,
		pb.OIDCClientAdminService_CreateOIDCClientSecret_FullMethodName,
		pb.OIDCClientAdminService_RevokeOIDCClientSecret_FullMethodName,
		pb.OIDCClientAdminService_AddOIDCClientAccessGrant_FullMethodName,
		pb.OIDCClientAdminService_RemoveOIDCClientAccessGrant_FullMethodName:
		return authzmodel.PlatformPermissionOIDCClientWrite, true
	default:
		return "", false
	}
}
