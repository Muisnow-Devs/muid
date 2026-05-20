package log

import (
	"context"
	"log/slog"
	"sync/atomic"
)

type loggerCtxKey struct{}

var defaultLogger atomic.Pointer[slog.Logger]

func init() {
	defaultLogger.Store(slog.Default())
}

// Default returns the process-wide slog logger used when none is stored on ctx.
func Default() *slog.Logger {
	return defaultLogger.Load()
}

// SetDefault replaces the process-wide logger (e.g. from cmd/*/main after configuring slog).
func SetDefault(l *slog.Logger) {
	if l == nil {
		l = slog.Default()
	}
	defaultLogger.Store(l)
}

// WithLogger returns a child context carrying l for [Logger] / [LoggerFromContext].
func WithLogger(ctx context.Context, l *slog.Logger) context.Context {
	if ctx == nil || l == nil {
		return ctx
	}
	return context.WithValue(ctx, loggerCtxKey{}, l)
}

// LoggerFromContext returns a logger previously stored with [WithLogger].
func LoggerFromContext(ctx context.Context) (*slog.Logger, bool) {
	if ctx == nil {
		return nil, false
	}
	l, ok := ctx.Value(loggerCtxKey{}).(*slog.Logger)
	return l, ok && l != nil
}

// Logger returns the request-scoped logger from ctx when present, otherwise [Default]
// enriched with trace_id and attrs from [WithAttrs] when available.
func Logger(ctx context.Context) *slog.Logger {
	var l *slog.Logger
	if scoped, ok := LoggerFromContext(ctx); ok {
		l = scoped
	} else {
		l = Default()
		if tid, ok := FromContext(ctx); ok && tid != "" {
			l = l.With("trace_id", tid)
		}
	}
	if attrs := attrsFromContext(ctx); len(attrs) > 0 {
		l = l.With(attrsAsAny(attrs)...)
	}
	return l
}
