package grpcutils_test

import (
	"context"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	grpcutils "sanzi.io/muid/pkg/grpc_utils"
	"sanzi.io/muid/pkg/log"
)

func TestTraceMetadataInterceptor_sendsTraceIDHeader(t *testing.T) {
	t.Parallel()

	const traceID = "test-trace-abc"

	// Capture the header metadata set during the RPC.
	var captured metadata.MD
	handler := func(ctx context.Context, req any) (any, error) {
		return "ok", nil
	}

	// grpc.SetHeader writes into an outgoing header MD stored on the context.
	// Use grpc.NewContextWithServerTransportStream so the test context supports it.
	ss := &fakeServerTransportStream{method: "/test.Service/Method"}
	ctx := grpc.NewContextWithServerTransportStream(context.Background(), ss)
	ctx = log.With(ctx, traceID)

	info := &grpc.UnaryServerInfo{FullMethod: ss.method}
	_, err := grpcutils.TraceMetadataInterceptor(ctx, nil, info, handler)
	if err != nil {
		t.Fatalf("interceptor returned error: %v", err)
	}

	captured = ss.headerMD
	vals := captured.Get(log.TraceIDKey)
	if len(vals) == 0 {
		t.Fatalf("expected %q header in response metadata, got none", log.TraceIDKey)
	}
	if vals[0] != traceID {
		t.Fatalf("expected trace id %q, got %q", traceID, vals[0])
	}
}

func TestTraceMetadataInterceptor_noTraceID_doesNotSetHeader(t *testing.T) {
	t.Parallel()

	handler := func(ctx context.Context, req any) (any, error) { return "ok", nil }

	ss := &fakeServerTransportStream{method: "/test.Service/Method"}
	ctx := grpc.NewContextWithServerTransportStream(context.Background(), ss)
	// No trace id injected.

	info := &grpc.UnaryServerInfo{FullMethod: ss.method}
	_, err := grpcutils.TraceMetadataInterceptor(ctx, nil, info, handler)
	if err != nil {
		t.Fatalf("interceptor returned error: %v", err)
	}

	if vals := ss.headerMD.Get(log.TraceIDKey); len(vals) != 0 {
		t.Fatalf("expected no %q header, got %v", log.TraceIDKey, vals)
	}
}

// fakeServerTransportStream is a minimal grpc.ServerTransportStream that
// captures headers set via grpc.SetHeader.
type fakeServerTransportStream struct {
	method   string
	headerMD metadata.MD
}

func (f *fakeServerTransportStream) Method() string { return f.method }
func (f *fakeServerTransportStream) SetHeader(md metadata.MD) error {
	f.headerMD = metadata.Join(f.headerMD, md)
	return nil
}
func (f *fakeServerTransportStream) SendHeader(md metadata.MD) error {
	f.headerMD = metadata.Join(f.headerMD, md)
	return nil
}
func (f *fakeServerTransportStream) SetTrailer(md metadata.MD) error { return nil }
