package tracing

import (
	"context"
	"strings"

	"google.golang.org/grpc/metadata"
)

type incomingMDKey struct{}

// WithIncomingGRPCMetadata stores incoming gRPC metadata on ctx for trace extraction.
func WithIncomingGRPCMetadata(ctx context.Context) context.Context {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok || len(md) == 0 {
		return ctx
	}
	return context.WithValue(ctx, incomingMDKey{}, md)
}

// GRPCMetadataCarrier adapts incoming metadata for W3C trace propagation.
type GRPCMetadataCarrier metadata.MD

func (c GRPCMetadataCarrier) Get(key string) string {
	vals := metadata.MD(c).Get(strings.ToLower(key))
	if len(vals) == 0 {
		return ""
	}
	return vals[0]
}

func (c GRPCMetadataCarrier) Set(key, value string) {
	md := metadata.MD(c)
	md.Set(strings.ToLower(key), value)
}

func (c GRPCMetadataCarrier) Keys() []string {
	out := make([]string, 0, len(c))
	for k := range c {
		out = append(out, k)
	}
	return out
}

// IncomingGRPCMetadataCarrier returns a carrier when metadata was stored on ctx.
func IncomingGRPCMetadataCarrier(ctx context.Context) (GRPCMetadataCarrier, bool) {
	md, ok := ctx.Value(incomingMDKey{}).(metadata.MD)
	if !ok || len(md) == 0 {
		return nil, false
	}
	return GRPCMetadataCarrier(md), true
}
