package tracing_test

import (
	"context"
	"testing"

	"sanzi.io/muid/pkg/shared/tracing"
)

func TestStartSpan_usesTracerFromContext(t *testing.T) {
	t.Parallel()

	tr := tracing.NewNoopTracer(tracing.NoopConfig{})
	ctx := tracing.ContextWithTracer(context.Background(), tr)

	ctx, span := tracing.StartSpan(ctx, "test.op")
	span.End()

	if got := tracing.NoopSpanCount(tr); got < 1 {
		t.Fatalf("expected at least 1 span, got %d", got)
	}
	_, ok := tracing.SpanFromContext(ctx)
	if !ok {
		t.Fatal("expected span on context")
	}
}

func TestWithSpanName(t *testing.T) {
	t.Parallel()

	ctx := tracing.WithSpanName(context.Background(), "custom.tx")
	name, ok := tracing.SpanNameFromContext(ctx)
	if !ok || name != "custom.tx" {
		t.Fatalf("got name=%q ok=%v", name, ok)
	}
}
