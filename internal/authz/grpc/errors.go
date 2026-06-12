package authzgrpc

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"sanzi.io/muid/internal/authz/policy"
	grpcutils "sanzi.io/muid/pkg/grpc_utils"
	"sanzi.io/muid/pkg/log"
	"sanzi.io/muid/pkg/shared/authzmodel"
)

// mapPolicyError converts policy sentinels to gRPC statuses with static
// messages; anything unexpected is logged and hidden behind Internal.
func mapPolicyError(ctx context.Context, op string, err error) error {
	switch {
	case errors.Is(err, policy.ErrPermissionDenied):
		return status.Error(codes.PermissionDenied, "permission denied")
	case errors.Is(err, policy.ErrOrganizationNotFound):
		return status.Error(codes.NotFound, "organization not found")
	case errors.Is(err, policy.ErrRoleNotFound):
		return status.Error(codes.NotFound, "role not found")
	case errors.Is(err, policy.ErrNotMember):
		return status.Error(codes.NotFound, "member not found")
	case errors.Is(err, policy.ErrOrganizationExists):
		return status.Error(codes.AlreadyExists, "organization already exists")
	case errors.Is(err, policy.ErrRoleExists):
		return status.Error(codes.AlreadyExists, "role already exists")
	case errors.Is(err, policy.ErrAlreadyMember):
		return status.Error(codes.AlreadyExists, "user is already a member")
	case errors.Is(err, policy.ErrSystemRoleImmutable):
		return status.Error(codes.FailedPrecondition, "system roles cannot be modified")
	case errors.Is(err, policy.ErrRoleInUse):
		return status.Error(codes.FailedPrecondition, "role is still assigned to members")
	case errors.Is(err, policy.ErrLastOwner):
		return status.Error(codes.FailedPrecondition, "organization must keep at least one owner")
	case errors.Is(err, policy.ErrUnknownPermission):
		return status.Error(codes.InvalidArgument, "unknown permission")
	case errors.Is(err, policy.ErrInvalidRule):
		return status.Error(codes.InvalidArgument, "invalid rule")
	case errors.Is(err, policy.ErrInvalidPageToken):
		return status.Error(codes.InvalidArgument, "invalid page token")
	case errors.Is(err, policy.ErrInvalidConfig):
		return status.Error(codes.InvalidArgument, "invalid policy configuration")
	case errors.Is(err, authzmodel.ErrInvalidPermission):
		return status.Error(codes.InvalidArgument, "invalid permission")
	default:
		log.LogUnexpected(ctx, op, err.Error())
		return grpcutils.GRPCInternalError()
	}
}
