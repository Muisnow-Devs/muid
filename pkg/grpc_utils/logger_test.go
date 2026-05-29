package grpcutils

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"sanzi.io/muid/pkg/log"
)

func TestLoggingInterceptor_structured(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	prev := log.Default()
	t.Cleanup(func() { log.SetDefault(prev) })

	log.SetDefault(
		slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})),
	)

	ctx := log.With(context.Background(), "tid-grpc")
	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}
	handler := func(ctx context.Context, req any) (any, error) {
		return "ok", status.Error(codes.NotFound, "missing")
	}

	ic := LoggingInterceptor()
	_, err := ic(ctx, nil, info, handler)
	if err == nil {
		t.Fatal("expected handler error")
	}

	out := buf.String()
	// go-grpc-middleware/v2 splits the full method into grpc.service and grpc.method
	// fields. trace_id comes from the pkg/log adapter reading it from ctx.
	for _, want := range []string{
		"trace_id=tid-grpc",
		"grpc.service=test.Service",
		"grpc.method=Method",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("log missing %q in %q", want, out)
		}
	}
}
