package log

import (
	"context"
	"log/slog"

	"github.com/google/uuid"
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

// ProfileID logs a full profile id (UUID).
func ProfileID(id uuid.UUID) slog.Attr {
	return slog.String("profile_id", id.String())
}

// UserID logs a full user id (UUID).
func UserID(id uuid.UUID) slog.Attr {
	return slog.String("user_id", id.String())
}

// TransitionID logs a full auth transition id (UUID).
func TransitionID(id uuid.UUID) slog.Attr {
	return slog.String("transition_id", id.String())
}
