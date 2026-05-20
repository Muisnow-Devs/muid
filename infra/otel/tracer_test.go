package oteltrace_test

import (
	"context"
	"errors"
	"testing"

	oteltrace "sanzi.io/muid/infra/otel"
	"sanzi.io/muid/pkg/shared/tracing"
)

func TestNewTracer_disabledReturnsNoop(t *testing.T) {
	t.Parallel()

	tr, err := oteltrace.NewTracer(oteltrace.Config{Enabled: false})
	if err != nil {
		t.Fatalf("NewTracer: %v", err)
	}
	_, span := tr.Start(context.Background(), "x")
	span.End()
	if err := tr.Shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
}

func TestNewTracer_stdout(t *testing.T) {
	t.Parallel()

	tr, err := oteltrace.NewTracer(oteltrace.Config{
		Enabled:     true,
		ServiceName: "muid-test",
		Exporter:    "stdout",
	})
	if err != nil {
		t.Fatalf("NewTracer: %v", err)
	}
	t.Cleanup(func() {
		_ = tr.Shutdown(context.Background())
	})

	_, span := tr.Start(context.Background(), "ping")
	span.End()
}

func TestNewTracer_invalidOTLP(t *testing.T) {
	t.Parallel()

	_, err := oteltrace.NewTracer(oteltrace.Config{
		Enabled:     true,
		ServiceName: "muid-test",
		Exporter:    "otlp",
	})
	if !errors.Is(err, tracing.ErrInvalidConfig) {
		t.Fatalf("expected invalid config, got %v", err)
	}
}
