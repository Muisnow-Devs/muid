package tracing

import "context"

type tracerCtxKey struct{}

// ContextWithTracer stores tracer on ctx for [TracerFromContext] and [StartSpan].
func ContextWithTracer(ctx context.Context, tr Tracer) context.Context {
	if ctx == nil || tr == nil {
		return ctx
	}
	return context.WithValue(ctx, tracerCtxKey{}, tr)
}

// TracerFromContext returns the tracer installed by the gRPC interceptor or bootstrap.
func TracerFromContext(ctx context.Context) (Tracer, bool) {
	if ctx == nil {
		return nil, false
	}
	tr, ok := ctx.Value(tracerCtxKey{}).(Tracer)
	return tr, ok && tr != nil
}

// StartSpan starts a child span using the tracer on ctx (noop when missing).
func StartSpan(ctx context.Context, name string, opts ...SpanOption) (context.Context, Span) {
	tr, ok := TracerFromContext(ctx)
	if !ok {
		tr = NewNoopTracer(NoopConfig{})
	}
	allOpts := append([]SpanOption{WithSpanKind(SpanKindInternal)}, opts...)
	return tr.Start(ctx, name, allOpts...)
}
