package oteltrace

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.40.0"
	oteltrace "go.opentelemetry.io/otel/trace"

	"sanzi.io/muid/pkg/log"
	"sanzi.io/muid/pkg/shared/tracing"
)

// NewTracer builds an OpenTelemetry SDK tracer or a noop tracer when disabled.
func NewTracer(cfg Config) (tracing.Tracer, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}
	if !cfg.Enabled || strings.EqualFold(cfg.Exporter, "noop") {
		return tracing.NewNoopTracer(tracing.NoopConfig{Debug: cfg.Debug}), nil
	}

	exporter, err := newExporter(cfg)
	if err != nil {
		return nil, errors.Join(tracing.ErrExporterInit, err)
	}

	res, err := resource.New(context.Background(),
		resource.WithAttributes(semconv.ServiceName(cfg.ServiceName)),
	)
	if err != nil {
		return nil, errors.Join(tracing.ErrExporterInit, err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	return &otelTracer{
		provider: tp,
		tracer:   tp.Tracer("sanzi.io/muid"),
		debug:    cfg.Debug,
	}, nil
}

func validateConfig(cfg Config) error {
	if !cfg.Enabled || strings.EqualFold(cfg.Exporter, "noop") {
		return nil
	}
	if strings.TrimSpace(cfg.ServiceName) == "" {
		return tracing.ErrInvalidConfig
	}
	exp := strings.ToLower(strings.TrimSpace(cfg.Exporter))
	if exp == "otlp" && strings.TrimSpace(cfg.OTLPEndpoint) == "" {
		return tracing.ErrInvalidConfig
	}
	if exp != "" && exp != "otlp" && exp != "stdout" {
		return tracing.ErrInvalidConfig
	}
	return nil
}

func newExporter(cfg Config) (sdktrace.SpanExporter, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.Exporter)) {
	case "otlp":
		opts := []otlptracehttp.Option{}
		if ep := strings.TrimSpace(cfg.OTLPEndpoint); ep != "" {
			opts = append(opts, otlptracehttp.WithEndpoint(trimOTLPHost(ep)))
			if strings.HasPrefix(ep, "http://") {
				opts = append(opts, otlptracehttp.WithInsecure())
			}
		}
		return otlptracehttp.New(context.Background(), opts...)
	case "", "stdout":
		return stdouttrace.New(stdouttrace.WithPrettyPrint())
	default:
		return nil, tracing.ErrInvalidConfig
	}
}

func trimOTLPHost(endpoint string) string {
	endpoint = strings.TrimSpace(endpoint)
	endpoint = strings.TrimPrefix(endpoint, "https://")
	endpoint = strings.TrimPrefix(endpoint, "http://")
	if i := strings.Index(endpoint, "/"); i >= 0 {
		endpoint = endpoint[:i]
	}
	return endpoint
}

type otelTracer struct {
	provider *sdktrace.TracerProvider
	tracer   oteltrace.Tracer
	debug    bool
}

func (t *otelTracer) Start(ctx context.Context, name string, opts ...tracing.SpanOption) (context.Context, tracing.Span) {
	if carrier, ok := tracing.IncomingGRPCMetadataCarrier(ctx); ok {
		ctx = otel.GetTextMapPropagator().Extract(ctx, carrier)
	}

	cfg := tracing.ApplySpanOptions(opts)
	otelOpts := []oteltrace.SpanStartOption{
		oteltrace.WithSpanKind(mapSpanKind(cfg.Kind)),
	}
	if len(cfg.Attrs) > 0 {
		otelOpts = append(otelOpts, oteltrace.WithAttributes(attrsToOTel(cfg.Attrs)...))
	}
	if tid, ok := log.FromContext(ctx); ok && tid != "" {
		otelOpts = append(otelOpts, oteltrace.WithAttributes(attribute.String("muid.log_trace_id", tid)))
	}

	ctx, otelSpan := t.tracer.Start(ctx, name, otelOpts...)
	span := &otelSpanWrap{span: otelSpan, debug: t.debug || cfg.Debug}
	ctx = tracing.ContextWithSpan(ctx, span)
	if span.debug {
		log.Logger(ctx).Debug("trace span start",
			slog.String("span", name),
			slog.String("tracer", "otel"),
			slog.String("trace_id", otelSpan.SpanContext().TraceID().String()),
		)
	}
	return ctx, span
}

func (t *otelTracer) Shutdown(ctx context.Context) error {
	if t.provider == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return t.provider.Shutdown(ctx)
}

type otelSpanWrap struct {
	span  oteltrace.Span
	debug bool
}

func (s *otelSpanWrap) End() {
	s.span.End()
}

func (s *otelSpanWrap) SetAttributes(attrs ...tracing.Attr) {
	s.span.SetAttributes(attrsToOTel(attrs)...)
}

func (s *otelSpanWrap) RecordError(err error) {
	if err == nil {
		return
	}
	s.span.RecordError(err)
	s.span.SetStatus(codes.Error, err.Error())
}

func (s *otelSpanWrap) SetDebug(enabled bool) {
	s.debug = enabled
}

func mapSpanKind(kind tracing.SpanKind) oteltrace.SpanKind {
	switch kind {
	case tracing.SpanKindServer:
		return oteltrace.SpanKindServer
	case tracing.SpanKindClient:
		return oteltrace.SpanKindClient
	case tracing.SpanKindInternal:
		return oteltrace.SpanKindInternal
	default:
		return oteltrace.SpanKindUnspecified
	}
}

func attrsToOTel(attrs []tracing.Attr) []attribute.KeyValue {
	out := make([]attribute.KeyValue, 0, len(attrs))
	for _, a := range attrs {
		switch v := a.Value.(type) {
		case string:
			out = append(out, attribute.String(a.Key, v))
		case int:
			out = append(out, attribute.Int64(a.Key, int64(v)))
		case int64:
			out = append(out, attribute.Int64(a.Key, v))
		case bool:
			out = append(out, attribute.Bool(a.Key, v))
		case float64:
			out = append(out, attribute.Float64(a.Key, v))
		default:
			out = append(out, attribute.String(a.Key, slog.AnyValue(v).String()))
		}
	}
	return out
}
