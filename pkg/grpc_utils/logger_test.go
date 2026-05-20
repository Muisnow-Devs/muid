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

func TestLoggerInterceptor_structured(t *testing.T) {
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

	_, err := LoggerInterceptor(ctx, nil, info, handler)
	if err == nil {
		t.Fatal("expected handler error")
	}

	out := buf.String()
	for _, want := range []string{
		"trace_id=tid-grpc",
		"method=/test.Service/Method",
		"msg=\"grpc request\"",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("log missing %q in %q", want, out)
		}
	}
}
