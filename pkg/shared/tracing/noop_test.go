package tracing_test

import (
	"context"
	"errors"
	"testing"

	"sanzi.io/muid/pkg/shared/tracing"
)

func TestNoopTracer_StartEnd(t *testing.T) {
	t.Parallel()

	tr := tracing.NewNoopTracer(tracing.NoopConfig{})
	ctx, span := tr.Start(context.Background(), "test.op",
		tracing.WithAttributes(tracing.StringAttr("k", "v")),
	)
	span.SetAttributes(tracing.BoolAttr("done", true))
	span.RecordError(errors.New("ignored"))
	span.End()

	got, ok := tracing.SpanFromContext(ctx)
	if !ok || got == nil {
		t.Fatal("expected span on context")
	}
}

func TestNoopTracer_Shutdown(t *testing.T) {
	t.Parallel()

	tr := tracing.NewNoopTracer(tracing.NoopConfig{})
	if err := tr.Shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
}
