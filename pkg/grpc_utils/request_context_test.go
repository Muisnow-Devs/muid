package grpcutils

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestUnaryRequestContextInterceptor_enrichAndReject(t *testing.T) {
	t.Parallel()

	type ctxMarker struct{}
	var gotCtx context.Context
	interceptor := UnaryRequestContextInterceptor(map[string]RequestContextFunc{
		"/test.Service/Ok": func(ctx context.Context, _ string, _ any) (context.Context, error) {
			return context.WithValue(ctx, ctxMarker{}, "enriched"), nil
		},
		"/test.Service/Bad": func(_ context.Context, _ string, _ any) (context.Context, error) {
			return nil, status.Error(codes.InvalidArgument, "bad request")
		},
	})

	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Ok"}
	handler := func(ctx context.Context, _ any) (any, error) {
		gotCtx = ctx
		return "ok", nil
	}

	resp, err := interceptor(context.Background(), nil, info, handler)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != "ok" {
		t.Fatalf("resp: got %v", resp)
	}
	if gotCtx.Value(ctxMarker{}) != "enriched" {
		t.Fatal("handler did not receive enriched context")
	}

	info.FullMethod = "/test.Service/Bad"
	_, err = interceptor(context.Background(), nil, info, handler)
	if err == nil {
		t.Fatal("expected error")
	}
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.InvalidArgument {
		t.Fatalf("code: got %v want InvalidArgument", status.Code(err))
	}

	info.FullMethod = "/test.Service/Unknown"
	_, err = interceptor(context.Background(), nil, info, handler)
	if err != nil {
		t.Fatalf("unknown method should pass through: %v", err)
	}
}

func TestUnaryRequestContextInterceptor_nilHandlerMap(t *testing.T) {
	t.Parallel()

	interceptor := UnaryRequestContextInterceptor(nil)
	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/X"}
	_, err := interceptor(
		context.Background(),
		nil,
		info,
		func(ctx context.Context, _ any) (any, error) {
			if ctx == nil {
				return nil, errors.New("nil ctx")
			}
			return nil, nil
		},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
