package log

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
)

func TestLogger_traceIDFromContext(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	prev := Default()
	t.Cleanup(func() { SetDefault(prev) })

	SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))

	ctx := With(context.Background(), "tid-abc")
	Logger(ctx).Info("hello")

	if !strings.Contains(buf.String(), "trace_id=tid-abc") {
		t.Fatalf("log missing trace_id: %q", buf.String())
	}
}

func TestLogger_contextLoggerWins(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	prev := Default()
	t.Cleanup(func() { SetDefault(prev) })

	SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))

	scoped := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})).
		With("scope", "child")
	ctx := WithLogger(context.Background(), scoped)
	Logger(ctx).Info("scoped")

	if !strings.Contains(buf.String(), "scope=child") {
		t.Fatalf("expected scoped logger: %q", buf.String())
	}
}

func TestLogUnexpected_attrs(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	prev := Default()
	t.Cleanup(func() { SetDefault(prev) })

	SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelError})))

	ctx := With(context.Background(), "tid-1")
	LogUnexpected(ctx, "grpc panic", "boom", slog.String("method", "/svc/Rpc"))

	out := buf.String()
	for _, want := range []string{
		"level=ERROR",
		"msg=unexpected",
		"trace_id=tid-1",
		`reason="grpc panic"`,
		"detail=boom",
		"method=/svc/Rpc",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("log missing %q in %q", want, out)
		}
	}
}

func TestWithAttrs_mergedIntoLogUnexpected(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	prev := Default()
	t.Cleanup(func() { SetDefault(prev) })

	SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelError})))

	ctx := WithAttrs(context.Background(), slog.String("operation", "ingest"))
	LogUnexpected(ctx, "ingest failed", "timeout")

	out := buf.String()
	for _, want := range []string{
		"operation=ingest",
		`reason="ingest failed"`,
		"detail=timeout",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("log missing %q in %q", want, out)
		}
	}
}
