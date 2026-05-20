package grpcutils

import (
	"context"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/status"

	"sanzi.io/muid/pkg/shared/tracing"
)

// UnaryTracingInterceptor records RPC server spans when tracer is non-nil.
// Place immediately after [TraceUnaryInterceptor] so log trace_id is available as a span attribute.
func UnaryTracingInterceptor(tr tracing.Tracer) grpc.UnaryServerInterceptor {
	if tr == nil {
		tr = tracing.NewNoopTracer(tracing.NoopConfig{})
	}
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		ctx = tracing.ContextWithTracer(ctx, tr)
		ctx = tracing.WithIncomingGRPCMetadata(ctx)
		ctx, span := tr.Start(ctx, "grpc "+info.FullMethod,
			tracing.WithSpanKind(tracing.SpanKindServer),
			tracing.WithAttributes(
				tracing.StringAttr("rpc.system", "grpc"),
				tracing.StringAttr("rpc.method", info.FullMethod),
			),
		)
		defer span.End()

		start := time.Now()
		resp, err := handler(ctx, req)
		span.SetAttributes(tracing.Int64Attr("rpc.duration_ms", time.Since(start).Milliseconds()))
		if err != nil {
			span.RecordError(err)
			if st, ok := status.FromError(err); ok {
				span.SetAttributes(tracing.StringAttr("rpc.grpc_code", st.Code().String()))
			}
		}
		return resp, err
	}
}

// UnaryTracingClientInterceptor is a stub that starts client spans and injects W3C headers
// into outgoing metadata when the tracer supports propagation (OpenTelemetry global propagator).
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
