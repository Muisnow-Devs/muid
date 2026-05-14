package profilegrpc

import (
	"context"

	grpcutils "sanzi.io/muid/pkg/grpc_utils"
	"sanzi.io/muid/pkg/traceid"
)

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
