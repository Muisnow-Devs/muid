package grpcutils

import (
	"context"
	"log/slog"

	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	"google.golang.org/grpc"

	"sanzi.io/muid/pkg/log"
)

// interceptorLogger adapts pkg/log to the [logging.Logger] interface so that
// the go-grpc-middleware/v2 logging interceptor emits via the request-scoped
// slog logger (trace_id + WithAttrs fields are automatically included).
func interceptorLogger() logging.Logger {
	return logging.LoggerFunc(
		func(ctx context.Context, lvl logging.Level, msg string, fields ...any) {
			log.Logger(ctx).Log(ctx, slog.Level(lvl), msg, fields...)
		},
	)
}

// LoggingInterceptor returns a go-grpc-middleware/v2 logging unary server
// interceptor that forwards to the request-scoped pkg/log logger.
func LoggingInterceptor(opts ...logging.Option) grpc.UnaryServerInterceptor {
	return logging.UnaryServerInterceptor(interceptorLogger(), opts...)
}
