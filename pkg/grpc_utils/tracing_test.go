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

// TestTracerContextInterceptor_recordsSpan verifies that spans started inside
// the handler are recorded. Server-level OTel spans are created by
// otelgrpc.NewServerHandler; this interceptor only stores the tracer in ctx.
func TestTracerContextInterceptor_recordsSpan(t *testing.T) {
	t.Parallel()

	tr := tracing.NewNoopTracer(tracing.NoopConfig{Debug: true})
	handler := func(ctx context.Context, req any) (any, error) {
		_, span := tracing.StartSpan(ctx, "handler.work")
		span.SetDebug(true)
		span.End()
		return "ok", nil
	}

	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}
	ic := grpcutils.TracerContextInterceptor(tr)
	ctx := metadata.NewIncomingContext(
		context.Background(),
		metadata.Pairs("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"),
	)
	ctx = log.With(ctx, "corr-id")

	_, err := ic(ctx, nil, info, handler)
	if err != nil {
		t.Fatalf("handler err: %v", err)
	}

	// Only the handler child span is recorded; the server span is handled by otelgrpc.
	if tracing.NoopSpanCount(tr) < 1 {
		t.Fatalf("expected at least 1 span, got %d", tracing.NoopSpanCount(tr))
	}
}
