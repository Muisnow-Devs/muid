package grpcutils

import (
	"context"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"sanzi.io/muid/pkg/log"
)

// PanicRecoveryHandler is a [recovery.RecoveryHandlerFuncContext] that logs the
// panic via [log.LogUnexpected] and returns a fixed client-safe internal error.
// Use with [recovery.WithRecoveryHandlerContext] from
// github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/recovery.
func PanicRecoveryHandler(ctx context.Context, p any) error {
	log.LogUnexpected(ctx, "grpc panic", fmt.Sprintf("%v", p))
	return status.Error(codes.Internal, "internal error")
}
