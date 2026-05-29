package grpcutils_test

import (
	"context"
	"testing"

	"google.golang.org/grpc"

	grpcutils "sanzi.io/muid/pkg/grpc_utils"
	"sanzi.io/muid/pkg/shared/tracing"
)

func TestTracerContextInterceptor_storesTracerOnContext(t *testing.T) {
	t.Parallel()

	tr := tracing.NewNoopTracer(tracing.NoopConfig{})
	var gotTracer bool
	handler := func(ctx context.Context, req any) (any, error) {
		_, gotTracer = tracing.TracerFromContext(ctx)
		_, span := tracing.StartSpan(ctx, "handler.child")
		span.End()
		return nil, nil
	}

	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}
	ic := grpcutils.TracerContextInterceptor(tr)
	_, err := ic(context.Background(), nil, info, handler)
	if err != nil {
		t.Fatalf("interceptor: %v", err)
	}
	if !gotTracer {
		t.Fatal("expected tracer on handler context")
	}
	// Only the handler's child span is recorded. The server-level OTel span is
	// created by otelgrpc.NewServerHandler at the transport layer, not here.
	if tracing.NoopSpanCount(tr) < 1 {
		t.Fatalf("expected at least 1 span (handler child), got %d", tracing.NoopSpanCount(tr))
	}
}
