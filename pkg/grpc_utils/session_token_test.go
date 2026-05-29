package grpcutils_test

import (
	"context"
	"encoding/base64"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"sanzi.io/muid/internal/session"
	grpcutils "sanzi.io/muid/pkg/grpc_utils"
)

func validSessionWireToken(t *testing.T) string {
	t.Helper()
	sel := make([]byte, session.SelectorByteLength)
	val := make([]byte, session.ValidatorByteLength)
	for i := range sel {
		sel[i] = byte(i + 1)
	}
	for i := range val {
		val[i] = byte(i + 2)
	}
	return base64.RawURLEncoding.EncodeToString(
		sel,
	) + "." + base64.RawURLEncoding.EncodeToString(
		val,
	)
}

func incomingCtxWithAuth(t *testing.T, value string) context.Context {
	t.Helper()
	return metadata.NewIncomingContext(
		context.Background(),
		metadata.Pairs(grpcutils.AuthorizationMetadataKey, value),
	)
}

func TestSessionTokenInterceptor_noHeader(t *testing.T) {
	t.Parallel()
	ic := grpcutils.SessionTokenInterceptor()
	info := &grpc.UnaryServerInfo{FullMethod: "/svc/Method"}

	called := false
	_, err := ic(context.Background(), nil, info, func(ctx context.Context, _ any) (any, error) {
		called = true
		_, ok := grpcutils.WireSessionTokenFromContext(ctx)
		if ok {
			t.Error("expected no token in ctx when header absent")
		}
		return nil, nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Fatal("handler must be called when authorization header is absent")
	}
}

func TestSessionTokenInterceptor_wrongScheme(t *testing.T) {
	t.Parallel()
	ic := grpcutils.SessionTokenInterceptor()
	info := &grpc.UnaryServerInfo{FullMethod: "/svc/Method"}

	for _, hdr := range []string{
		"Bearer sometoken",
		"Basic dXNlcjpwYXNz",
		"noseparator",
	} {
		_, err := ic(
			incomingCtxWithAuth(t, hdr),
			nil,
			info,
			func(context.Context, any) (any, error) {
				t.Fatalf("handler must not be called for wrong scheme: %q", hdr)
				return nil, nil
			},
		)
		if status.Code(err) != codes.Unauthenticated {
			t.Errorf("scheme %q: got code %v, want Unauthenticated", hdr, status.Code(err))
		}
	}
}

func TestSessionTokenInterceptor_badFormat(t *testing.T) {
	t.Parallel()
	ic := grpcutils.SessionTokenInterceptor()
	info := &grpc.UnaryServerInfo{FullMethod: "/svc/Method"}

	_, err := ic(
		incomingCtxWithAuth(t, "Session bad.token"),
		nil,
		info,
		func(context.Context, any) (any, error) {
			t.Fatal("handler must not be called for malformed wire token")
			return nil, nil
		},
	)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("got code %v, want Unauthenticated", status.Code(err))
	}
}

func TestSessionTokenInterceptor_valid(t *testing.T) {
	t.Parallel()
	ic := grpcutils.SessionTokenInterceptor()
	info := &grpc.UnaryServerInfo{FullMethod: "/svc/Method"}
	wire := validSessionWireToken(t)

	var got string
	_, err := ic(
		incomingCtxWithAuth(t, "Session "+wire),
		nil,
		info,
		func(ctx context.Context, _ any) (any, error) {
			var ok bool
			got, ok = grpcutils.WireSessionTokenFromContext(ctx)
			if !ok {
				t.Fatal("expected token in ctx")
			}
			return nil, nil
		},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != wire {
		t.Fatalf("wire: got %q want %q", got, wire)
	}
}

func TestSessionTokenInterceptor_caseInsensitiveScheme(t *testing.T) {
	t.Parallel()
	ic := grpcutils.SessionTokenInterceptor()
	info := &grpc.UnaryServerInfo{FullMethod: "/svc/Method"}
	wire := validSessionWireToken(t)

	for _, scheme := range []string{"SESSION", "Session", "session"} {
		_, err := ic(
			incomingCtxWithAuth(t, scheme+" "+wire),
			nil,
			info,
			func(ctx context.Context, _ any) (any, error) {
				if _, ok := grpcutils.WireSessionTokenFromContext(ctx); !ok {
					t.Errorf("scheme %q: expected token in ctx", scheme)
				}
				return nil, nil
			},
		)
		if err != nil {
			t.Errorf("scheme %q: unexpected error: %v", scheme, err)
		}
	}
}
