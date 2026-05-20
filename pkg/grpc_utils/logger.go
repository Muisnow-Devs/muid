package grpcutils

import (
	"context"
	"log/slog"
	"time"

	"google.golang.org/grpc"

	"sanzi.io/muid/pkg/log"
)

func LoggerInterceptor(
	ctx context.Context,
	req any,
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (any, error) {
	start := time.Now()

	resp, err := handler(ctx, req)

	log.Logger(ctx).Info("grpc request",
		slog.String("method", info.FullMethod),
		slog.Duration("duration", time.Since(start)),
		slog.Any("err", err),
	)

	return resp, err
}
