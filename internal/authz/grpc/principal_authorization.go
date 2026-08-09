package authzgrpc

import (
	"context"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "sanzi.io/muid/api/proto/authz/v1"
	"sanzi.io/muid/pkg/audit"
	grpcutils "sanzi.io/muid/pkg/grpc_utils"
	"sanzi.io/muid/pkg/log"
)

const (
	platformOrganizationWrite = "platform/organization.write"
	platformPolicyRead        = "platform/policy.read"
	platformPolicyWrite       = "platform/policy.write"
	platformPolicyReload      = "platform/policy.reload"
)

type platformPermissionChecker interface {
	CheckPlatformPermission(context.Context, uuid.UUID, string) (bool, error)
}

// PrincipalAuditInterceptor attaches AuthZ-specific log and audit attributes
// after the shared transport interceptor has authenticated a user principal.
func PrincipalAuditInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		_ *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		userID, ok := grpcutils.RequestUserIDFromContext(ctx)
		if ok {
			ctx = log.WithAttrs(ctx, log.UserID(userID))
			ctx = audit.WithActor(ctx, userID)
		}
		return handler(ctx, req)
	}
}

// AdminAuthorizationInterceptor rechecks platform authority at the AuthZ
// boundary. Gateway checks are defense in depth and are never authoritative.
func AdminAuthorizationInterceptor(checker platformPermissionChecker) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		permission, adminMethod := adminPlatformPermission(info.FullMethod)
		if !adminMethod {
			return handler(ctx, req)
		}
		userID, ok := grpcutils.RequestUserIDFromContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "user identity required")
		}
		if checker == nil {
			log.LogUnexpected(ctx, "authz platform permission", "permission checker is nil")
			return nil, grpcutils.GRPCInternalError()
		}
		allowed, err := checker.CheckPlatformPermission(ctx, userID, permission)
		if err != nil {
			log.LogUnexpected(ctx, "authz platform permission", err.Error())
			return nil, grpcutils.GRPCInternalError()
		}
		if !allowed {
			return nil, status.Error(codes.PermissionDenied, "permission denied")
		}
		return handler(ctx, req)
	}
}

func adminPlatformPermission(fullMethod string) (string, bool) {
	switch fullMethod {
	case pb.AuthzAdminService_CreateOrganization_FullMethodName,
		pb.AuthzAdminService_DeleteOrganization_FullMethodName,
		pb.AuthzAdminService_SetOrganizationMember_FullMethodName:
		return platformOrganizationWrite, true
	case pb.AuthzAdminService_ListCasbinRules_FullMethodName:
		return platformPolicyRead, true
	case pb.AuthzAdminService_AddRawPolicies_FullMethodName,
		pb.AuthzAdminService_RemoveRawPolicies_FullMethodName:
		return platformPolicyWrite, true
	case pb.AuthzAdminService_ReloadPolicyConfig_FullMethodName:
		return platformPolicyReload, true
	default:
		return "", false
	}
}
