package log

import (
	"context"
	"log/slog"
)

type attrsKey struct{}

// WithAttrs returns a child context whose attrs are merged into [Logger] and [LogUnexpected].
func WithAttrs(ctx context.Context, attrs ...slog.Attr) context.Context {
	if ctx == nil || len(attrs) == 0 {
		return ctx
	}
	merged := append(append([]slog.Attr(nil), attrsFromContext(ctx)...), attrs...)
	return context.WithValue(ctx, attrsKey{}, merged)
}

func attrsFromContext(ctx context.Context) []slog.Attr {
	if ctx == nil {
		return nil
	}
	attrs, _ := ctx.Value(attrsKey{}).([]slog.Attr)
	return attrs
}

func attrsAsAny(attrs []slog.Attr) []any {
	if len(attrs) == 0 {
		return nil
	}
	out := make([]any, len(attrs))
	for i, a := range attrs {
		out[i] = a
	}
	return out
}

// UserIDPrefix logs a non-identifying prefix of a user id (first 8 runes when available).
func UserIDPrefix(userID string) slog.Attr {
	if len(userID) >= 8 {
		return slog.String("user_id_prefix", userID[:8])
	}
	return slog.String("user_id_prefix", userID)
}
