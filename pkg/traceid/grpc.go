package traceid

import (
	"context"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"sanzi.io/muid/pkg/shared"
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
	for _, key := range []string{"x-trace-id", "x-request-id"} {
		if vals := md.Get(key); len(vals) > 0 {
			if v := strings.TrimSpace(vals[0]); v != "" {
				return v
			}
		}
	}
	return ""
}
