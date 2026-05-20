package log

import (
	"context"
	"log/slog"
)

// LogUnexpected emits a structured error log for non-client-facing failures.
// Per-call attrs are merged with attrs from [WithAttrs] on ctx. Use only safe, non-secret values.
func LogUnexpected(ctx context.Context, reason, detail string, attrs ...slog.Attr) {
	args := []any{
		slog.String("reason", reason),
		slog.String("detail", detail),
	}
	args = append(args, attrsAsAny(attrs)...)
	Logger(ctx).Error("unexpected", args...)
}
