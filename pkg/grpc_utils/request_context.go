package grpcutils

import (
	"context"

	"google.golang.org/grpc"
)

// RequestContextFunc enriches ctx after protovalidate (parse IDs, attach log attrs, etc.).
// Return a non-nil error to abort the RPC before the handler runs.
type RequestContextFunc func(ctx context.Context, fullMethod string, req any) (context.Context, error)

// UnaryRequestContextInterceptor runs the registered enricher for [grpc.UnaryServerInfo.FullMethod].
func UnaryRequestContextInterceptor(
	handlers map[string]RequestContextFunc,
) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		enrich, ok := handlers[info.FullMethod]
		if !ok {
			return handler(ctx, req)
		}
		ctx, err := enrich(ctx, info.FullMethod, req)
		if err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}
