package traceid

import "context"

type ctxKey struct{}

// With returns a child context carrying traceID (non-empty).
func With(ctx context.Context, traceID string) context.Context {
	if traceID == "" {
		return ctx
	}
	return context.WithValue(ctx, ctxKey{}, traceID)
}

// TraceIDFromContext returns the trace id if present.
func TraceIDFromContext(ctx context.Context) (string, bool) {
	return FromContext(ctx)
}

// FromContext returns the trace id if present.
func FromContext(ctx context.Context) (string, bool) {
	if ctx == nil {
		return "", false
	}
	v, ok := ctx.Value(ctxKey{}).(string)
	if !ok || v == "" {
		return "", false
	}
	return v, true
}
