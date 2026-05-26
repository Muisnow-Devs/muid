package authngrpc

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "sanzi.io/muid/api/proto/authn/v1"
	sessionpb "sanzi.io/muid/api/proto/authn/v1/session"
	"sanzi.io/muid/internal/session"
	"sanzi.io/muid/pkg/clientmeta"
)

func validWireToken(t *testing.T) string {
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

func TestAuthnRequestContextInterceptor_requiredWireSession(t *testing.T) {
	t.Parallel()

	interceptor := AuthnRequestContextInterceptor()
	wire := validWireToken(t)

	req := &pb.GetAuthorizedSessionRequest{}
	tok := &sessionpb.SessionToken{}
	tok.SetValue(wire)
	req.SetSessionToken(tok)

	var got string
	info := &grpc.UnaryServerInfo{FullMethod: pb.AuthnService_GetAuthorizedSession_FullMethodName}
	_, err := interceptor(
		context.Background(),
		req,
		info,
		func(ctx context.Context, _ any) (any, error) {
			var ok bool
			got, ok = WireSessionFromContext(ctx)
			if !ok {
				t.Fatal("missing wire session on context")
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

func TestAuthnRequestContextInterceptor_requiredWireSession_principal(t *testing.T) {
	t.Parallel()

	interceptor := AuthnRequestContextInterceptor()
	wire := validWireToken(t)

	req := &pb.GetAuthenticatedPrincipalRequest{}
	tok := &sessionpb.SessionToken{}
	tok.SetValue(wire)
	req.SetSessionToken(tok)

	var got string
	info := &grpc.UnaryServerInfo{
		FullMethod: pb.AuthnService_GetAuthenticatedPrincipal_FullMethodName,
	}
	_, err := interceptor(
		context.Background(),
		req,
		info,
		func(ctx context.Context, _ any) (any, error) {
			var ok bool
			got, ok = WireSessionFromContext(ctx)
			if !ok {
				t.Fatal("missing wire session on context")
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

func TestAuthnRequestContextInterceptor_missingWireSession(t *testing.T) {
	t.Parallel()

	interceptor := AuthnRequestContextInterceptor()
	req := &pb.RevokeSessionRequest{}

	info := &grpc.UnaryServerInfo{FullMethod: pb.AuthnService_RevokeSession_FullMethodName}
	_, err := interceptor(context.Background(), req, info, func(context.Context, any) (any, error) {
		t.Fatal("handler should not run")
		return nil, nil
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code: got %v", status.Code(err))
	}
	if !strings.Contains(status.Convert(err).Message(), msgMissingSessionToken) {
		t.Fatalf("message: %v", status.Convert(err).Message())
	}
}

func TestAuthnRequestContextInterceptor_continueTransitionID(t *testing.T) {
	t.Parallel()

	interceptor := AuthnRequestContextInterceptor()
	req := &pb.ContinueAuthSessionRequest{}
	req.SetTransitionId("550e8400-e29b-41d4-a716-446655440000")

	info := &grpc.UnaryServerInfo{FullMethod: pb.AuthnService_ContinueAuthSession_FullMethodName}
	_, err := interceptor(
		context.Background(),
		req,
		info,
		func(ctx context.Context, _ any) (any, error) {
			id, ok := TransitionIDFromContext(ctx)
			if !ok {
				t.Fatal("missing transition id on context")
			}
			if id.String() != req.GetTransitionId() {
				t.Fatalf("transition id mismatch: %v", id)
			}
			return nil, nil
		},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAuthnRequestContextInterceptor_revokeFederatedWireSession(t *testing.T) {
	t.Parallel()

	interceptor := AuthnRequestContextInterceptor()
	wire := validWireToken(t)

	req := &pb.RevokeFederatedIdentityRequest{}
	tok := &sessionpb.SessionToken{}
	tok.SetValue(wire)
	req.SetSessionToken(tok)

	info := &grpc.UnaryServerInfo{
		FullMethod: pb.AuthnService_RevokeFederatedIdentity_FullMethodName,
	}
	_, err := interceptor(
		context.Background(),
		req,
		info,
		func(ctx context.Context, _ any) (any, error) {
			got, ok := WireSessionFromContext(ctx)
			if !ok || got != wire {
				t.Fatalf("wire session: got %q ok=%v", got, ok)
			}
			return nil, nil
		},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAuthnRequestContextInterceptor_startClientMeta(t *testing.T) {
	t.Parallel()

	interceptor := AuthnRequestContextInterceptor()
	req := &pb.StartAuthSessionRequest{}

	ctx := metadata.NewIncomingContext(
		context.Background(),
		metadata.Pairs(
			clientmeta.LocaleMetadataKey, "zh-TW",
			clientmeta.TimezoneMetadataKey, "Asia/Taipei",
			clientmeta.DeviceMetadataKey, "Chrome on macOS",
			clientmeta.LocationMetadataKey, "Taipei, TW",
			clientmeta.ClientIPMetadataKey, "203.0.113.9",
		),
	)

	info := &grpc.UnaryServerInfo{FullMethod: pb.AuthnService_StartAuthSession_FullMethodName}
	_, err := interceptor(
		ctx,
		req,
		info,
		func(ctx context.Context, _ any) (any, error) {
			meta, ok := clientmeta.FromContext(ctx)
			if !ok {
				t.Fatal("missing client meta on context")
			}
			if meta.Locale != "zh-TW" || meta.Timezone != "Asia/Taipei" {
				t.Fatalf("locale/timezone: %+v", meta)
			}
			if meta.Device != "Chrome on macOS" || meta.Location != "Taipei, TW" {
				t.Fatalf("device: %+v", meta)
			}
			if meta.IPAddress != "203.0.113.9" {
				t.Fatalf("ip: %q", meta.IPAddress)
			}
			return nil, nil
		},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAuthnRequestContextInterceptor_startInvalidTimezone(t *testing.T) {
	t.Parallel()

	interceptor := AuthnRequestContextInterceptor()
	req := &pb.StartAuthSessionRequest{}

	ctx := metadata.NewIncomingContext(
		context.Background(),
		metadata.Pairs(clientmeta.TimezoneMetadataKey, "Invalid/Zone"),
	)

	info := &grpc.UnaryServerInfo{FullMethod: pb.AuthnService_StartAuthSession_FullMethodName}
	_, err := interceptor(ctx, req, info, func(context.Context, any) (any, error) {
		t.Fatal("handler should not run")
		return nil, nil
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code: got %v", status.Code(err))
	}
}

func TestAuthnRequestContextInterceptor_invalidWireSession(t *testing.T) {
	t.Parallel()

	interceptor := AuthnRequestContextInterceptor()
	req := &pb.StartAuthSessionRequest{}
	tok := &sessionpb.SessionToken{}
	tok.SetValue("bad.token")
	req.SetSessionToken(tok)

	info := &grpc.UnaryServerInfo{FullMethod: pb.AuthnService_StartAuthSession_FullMethodName}
	_, err := interceptor(context.Background(), req, info, func(context.Context, any) (any, error) {
		t.Fatal("handler should not run")
		return nil, nil
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code: got %v", status.Code(err))
	}
}
