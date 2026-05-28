package grpcutils

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"sanzi.io/muid/pkg/log"
)

// TraceMetadataInterceptor sends the request-scoped trace id back to the
// caller as the "x-trace-id" gRPC response header.  It must be placed after
// [TraceUnaryInterceptor] in the chain so that the id is already present on
// the context.
func TraceMetadataInterceptor(
	ctx context.Context,
	req any,
	_ *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (any, error) {
	if tid, ok := log.FromContext(ctx); ok && tid != "" {
		grpc.SetHeader(ctx, metadata.Pairs(log.TraceIDKey, tid))
	}
	return handler(ctx, req)
}
