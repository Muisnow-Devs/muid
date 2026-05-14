package traceid

import (
	"context"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"sanzi.io/muid/pkg/shared"
)

const (
	TraceIDKey   = "x-trace-id"
	RequestIDKey = "x-request-id"
)

// UnaryServerInterceptor injects a trace id into context: prefers incoming
// metadata keys x-trace-id then x-request-id; otherwise generates a new id.
func UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		id := fromIncomingMetadata(ctx)
		if id == "" {
			id = shared.UUIDV7().String()
		}
		return handler(With(ctx, id), req)
	}
}

func fromIncomingMetadata(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	for _, key := range []string{TraceIDKey, RequestIDKey} {
		if vals := md.Get(key); len(vals) > 0 {
			if v := strings.TrimSpace(vals[0]); v != "" {
				return v
			}
		}
	}
	return ""
}

// UnaryClientInterceptor forwards the trace id from [FromContext] as outgoing
// gRPC metadata (x-trace-id) for downstream calls.
func UnaryClientInterceptor() grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		if id, ok := FromContext(ctx); ok {
			ctx = metadata.AppendToOutgoingContext(ctx, TraceIDKey, id)
		}
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}
