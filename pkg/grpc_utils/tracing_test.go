package grpcutils_test

import (
	"context"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	grpcutils "sanzi.io/muid/pkg/grpc_utils"
	"sanzi.io/muid/pkg/log"
	"sanzi.io/muid/pkg/shared/tracing"
)

func TestUnaryTracingInterceptor_recordsSpan(t *testing.T) {
	t.Parallel()

	tr := tracing.NewNoopTracer(tracing.NoopConfig{Debug: true})
	handler := func(ctx context.Context, req any) (any, error) {
		span, ok := tracing.SpanFromContext(ctx)
		if !ok {
			t.Fatal("missing span on context")
		}
		span.SetDebug(true)
		_ = span
		return "ok", nil
	}

	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}
	ic := grpcutils.UnaryTracingInterceptor(tr)
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"))
	ctx = log.With(ctx, "corr-id")

	_, err := ic(ctx, nil, info, handler)
	if err != nil {
		t.Fatalf("handler err: %v", err)
	}
}
