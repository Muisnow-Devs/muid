package grpcutils

import (
	"context"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/status"

	"sanzi.io/muid/pkg/shared/tracing"
)

// TracerContextInterceptor stores tr in context so handlers can retrieve it
// via [tracing.TracerFromContext] / [tracing.StartSpan].
// OTel spans are created at the stats-handler level by otelgrpc.NewServerHandler;
// this interceptor no longer creates its own server span.
func TracerContextInterceptor(tr tracing.Tracer) grpc.UnaryServerInterceptor {
	if tr == nil {
		tr = tracing.NewNoopTracer(tracing.NoopConfig{})
	}
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		return handler(tracing.ContextWithTracer(ctx, tr), req)
	}
}

// UnaryTracingClientInterceptor starts client spans and injects W3C headers
// into outgoing metadata when the tracer supports propagation.
func UnaryTracingClientInterceptor(tr tracing.Tracer) grpc.UnaryClientInterceptor {
	if tr == nil {
		tr = tracing.NewNoopTracer(tracing.NoopConfig{})
	}
	return func(
		ctx context.Context,
		method string,
		req, reply any,
		cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker,
		opts ...grpc.CallOption,
	) error {
		ctx = tracing.ContextWithTracer(ctx, tr)
		ctx, span := tr.Start(ctx, "grpc "+method,
			tracing.WithSpanKind(tracing.SpanKindClient),
			tracing.WithAttributes(
				tracing.StringAttr("rpc.system", "grpc"),
				tracing.StringAttr("rpc.method", method),
			),
		)
		defer span.End()

		start := time.Now()
		err := invoker(ctx, method, req, reply, cc, opts...)
		span.SetAttributes(tracing.Int64Attr("rpc.duration_ms", time.Since(start).Milliseconds()))
		if err != nil {
			span.RecordError(err)
			if st, ok := status.FromError(err); ok {
				span.SetAttributes(tracing.StringAttr("rpc.grpc_code", st.Code().String()))
			}
		}
		return err
	}
}
