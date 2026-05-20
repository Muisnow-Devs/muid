package grpcutils

import (
	"context"
	"fmt"
	"log/slog"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"sanzi.io/muid/pkg/log"
)

func RecoveryInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (resp interface{}, err error) {
	defer func() {
		if r := recover(); r != nil {
			log.LogUnexpected(
				ctx,
				"grpc panic",
				fmt.Sprintf("%v", r),
				slog.String("method", info.FullMethod),
			)
			err = status.Error(codes.Internal, "internal error")
		}
	}()

	return handler(ctx, req)
}
