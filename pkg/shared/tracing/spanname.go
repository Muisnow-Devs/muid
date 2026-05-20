package tracing

import "context"

type spanNameCtxKey struct{}

// WithSpanName sets the span name used by [pkg/enttx] transaction helpers.
func WithSpanName(ctx context.Context, name string) context.Context {
	if ctx == nil || name == "" {
		return ctx
	}
	return context.WithValue(ctx, spanNameCtxKey{}, name)
}

// SpanNameFromContext returns an explicit transaction span name when set.
func SpanNameFromContext(ctx context.Context) (string, bool) {
	if ctx == nil {
		return "", false
	}
	name, ok := ctx.Value(spanNameCtxKey{}).(string)
	return name, ok && name != ""
}
