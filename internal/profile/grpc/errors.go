package profilegrpc

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"sanzi.io/muid/internal/profile/core"
	"sanzi.io/muid/internal/profile/updatemask"
	grpcutils "sanzi.io/muid/pkg/grpc_utils"
	"sanzi.io/muid/pkg/log"
)

// mapProfileError converts profile domain sentinels to gRPC statuses with
// static messages; anything unexpected is logged and hidden behind Internal.
func mapProfileError(ctx context.Context, op string, err error) error {
	if ia, ok := errors.AsType[core.InvalidArgumentError](err); ok {
		return status.Error(codes.InvalidArgument, ia.Error())
	}

	switch {
	case errors.Is(err, updatemask.ErrEmptyMask):
		return status.Error(
			codes.InvalidArgument,
			"update_mask must list at least one field path",
		)
	case errors.Is(err, core.ErrUnsupportedMaskPath):
		return status.Error(codes.InvalidArgument, "unsupported update_mask path")
	case errors.Is(err, updatemask.ErrUnknownPath):
		return status.Error(codes.InvalidArgument, "unknown update_mask path")
	case errors.Is(err, core.ErrUpdateConflict):
		return status.Error(codes.AlreadyExists, "conflicting update value already in use")
	default:
		log.LogUnexpected(ctx, op, err.Error())
		return grpcutils.GRPCInternalError()
	}
}

// mapOrganizationProfileError converts organization-profile sentinels to gRPC
// statuses. It reuses the shared mask/conflict/invalid-argument handling and
// adds the organization-profile not-found / already-exists cases.
func mapOrganizationProfileError(ctx context.Context, op string, err error) error {
	switch {
	case errors.Is(err, core.ErrOrganizationProfileNotFound):
		return status.Error(codes.NotFound, "organization profile not found")
	case errors.Is(err, core.ErrOrganizationProfileExists):
		return status.Error(codes.AlreadyExists, "organization profile already exists")
	case errors.Is(err, core.ErrSlugExhausted):
		return status.Error(
			codes.ResourceExhausted,
			"could not allocate a unique organization slug",
		)
	default:
		return mapProfileError(ctx, op, err)
	}
}

// mapAvatarError converts avatar upload sentinels to gRPC statuses.
func mapAvatarError(ctx context.Context, op string, err error) error {
	if ia, ok := errors.AsType[core.InvalidArgumentError](err); ok {
		return status.Error(codes.InvalidArgument, ia.Error())
	}

	switch {
	case errors.Is(err, core.ErrAvatarNotConfigured):
		return status.Error(
			codes.FailedPrecondition,
			"avatar uploads are not configured (set PROFILE_R2_* variables)",
		)
	case errors.Is(err, core.ErrProfileNotFound):
		return status.Error(codes.NotFound, "profile not found")
	case errors.Is(err, core.ErrObjectKeyNotOwned):
		return status.Error(codes.InvalidArgument, "object_key does not belong to this user")
	case errors.Is(err, core.ErrAvatarSessionNotFound):
		return status.Error(codes.NotFound, "avatar row not found")
	case errors.Is(err, core.ErrAvatarSessionCompleted):
		return status.Error(codes.FailedPrecondition, "upload session already completed")
	case errors.Is(err, core.ErrAvatarObjectMissing):
		return status.Error(codes.FailedPrecondition, "object not found in storage")
	case errors.Is(err, core.ErrInvalidAvatarImage):
		return status.Error(codes.InvalidArgument, "invalid avatar image")
	default:
		log.LogUnexpected(ctx, op, err.Error())
		return grpcutils.GRPCInternalError()
	}
}
