package profilegrpc

import (
	"context"

	"github.com/google/uuid"
	grpcutils "sanzi.io/muid/pkg/grpc_utils"
	"sanzi.io/muid/pkg/traceid"
)

func internalErrorWithUserId(
	ctx context.Context,
	err error,
	reason string,
	userID uuid.UUID,
	extra ...string,
) error {
	pairs := append([]string{"user_id_prefix", userIDPrefix(userID.String())}, extra...)
	return grpcInternal(ctx, reason, err, pairs...)
}

func grpcInternal(ctx context.Context, reason string, err error, pairs ...string) error {
	detail := ""
	if err != nil {
		detail = err.Error()
	}
	traceid.LogUnexpected(ctx, reason, detail, pairs...)
	return grpcutils.GRPCInternalError()
}

func userIDPrefix(userID string) string {
	if len(userID) >= 8 {
		return userID[:8]
	}
	return userID
}
