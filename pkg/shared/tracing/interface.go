// Package tracing defines a swappable distributed-tracing contract (OpenTelemetry, noop, debug).
package tracing

import "context"

// Tracer starts spans and shuts down exporters when implemented by a provider backend.
type Tracer interface {
	Start(ctx context.Context, name string, opts ...SpanOption) (context.Context, Span)
	Shutdown(ctx context.Context) error
}

// Span is an in-flight operation; call End when the work completes.
type Span interface {
	End()
	SetAttributes(attrs ...Attr)
	RecordError(err error)
	// SetDebug enables verbose span lifecycle logging (noop/debug tracers; OTel may log extra detail).
	SetDebug(enabled bool)
}

// SpanKind classifies span role (server, client, internal, …).
type SpanKind int

const (
	SpanKindUnspecified SpanKind = iota
	SpanKindInternal
	SpanKindServer
	SpanKindClient
)

// Attr is a string-keyed attribute attached to a span.
type Attr struct {
	Key   string
	Value any
}
