package tracing

import (
	"context"
	"log/slog"
	"sync/atomic"

	"sanzi.io/muid/pkg/log"
)

// NoopConfig configures [NewNoopTracer].
type NoopConfig struct {
	Debug bool
}

// NewNoopTracer returns a tracer that records no telemetry. When Debug is true, span
// lifecycle is logged at debug level via [pkg/log].
func NewNoopTracer(cfg NoopConfig) Tracer {
	return &noopTracer{debug: cfg.Debug}
}

type noopTracer struct {
	debug        bool
	spansStarted atomic.Int64
}

// SpanCount returns the number of spans started (testing / debug).
func (t *noopTracer) SpanCount() int64 {
	return t.spansStarted.Load()
}

// NoopSpanCount reads span starts from a noop tracer when available.
func NoopSpanCount(tr Tracer) int64 {
	if c, ok := tr.(interface{ SpanCount() int64 }); ok {
		return c.SpanCount()
	}
	return 0
}

func (t *noopTracer) Start(
	ctx context.Context,
	name string,
	opts ...SpanOption,
) (context.Context, Span) {
	t.spansStarted.Add(1)
	cfg := applySpanOptions(opts)
	span := &noopSpan{
		name:  name,
		debug: t.debug || cfg.Debug,
		attrs: append([]Attr(nil), cfg.Attrs...),
	}
	ctx = ContextWithSpan(ctx, span)
	if span.debug {
		log.Logger(ctx).Debug("trace span start",
			slog.String("span", name),
			slog.String("tracer", "noop"),
		)
	}
	return ctx, span
}

func (t *noopTracer) Shutdown(context.Context) error {
	return nil
}

type noopSpan struct {
	name  string
	debug bool
	attrs []Attr
}

func (s *noopSpan) End() {
	if !s.debug {
		return
	}
	log.Default().Debug("trace span end",
		slog.String("span", s.name),
		slog.String("tracer", "noop"),
	)
}

func (s *noopSpan) SetAttributes(attrs ...Attr) {
	s.attrs = append(s.attrs, attrs...)
}

func (s *noopSpan) RecordError(err error) {
	if err == nil || !s.debug {
		return
	}
	log.Default().Debug("trace span error",
		slog.String("span", s.name),
		slog.Any("err", err),
	)
}

func (s *noopSpan) SetDebug(enabled bool) {
	s.debug = enabled
}

type spanCtxKey struct{}

// ContextWithSpan stores span on ctx for [SpanFromContext].
func ContextWithSpan(ctx context.Context, span Span) context.Context {
	if ctx == nil || span == nil {
		return ctx
	}
	return context.WithValue(ctx, spanCtxKey{}, span)
}

// SpanFromContext returns the active span when present.
func SpanFromContext(ctx context.Context) (Span, bool) {
	if ctx == nil {
		return nil, false
	}
	span, ok := ctx.Value(spanCtxKey{}).(Span)
	return span, ok && span != nil
}
