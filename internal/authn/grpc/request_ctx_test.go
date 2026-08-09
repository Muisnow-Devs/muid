package authngrpc

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "sanzi.io/muid/api/proto/authn/v1"
	sessionpb "sanzi.io/muid/api/proto/authn/v1/session"
	"sanzi.io/muid/internal/identity/issuer"
	"sanzi.io/muid/internal/session"
	"sanzi.io/muid/pkg/clientmeta"
	grpcutils "sanzi.io/muid/pkg/grpc_utils"
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

// ctxWithHeaderToken mirrors the interceptor chain and stores the wire token on ctx.
func ctxWithHeaderToken(t *testing.T, wire string) context.Context {
	t.Helper()
	ic := grpcutils.SessionTokenInterceptor()
	inCtx := metadata.NewIncomingContext(
		context.Background(),
		metadata.Pairs(grpcutils.AuthorizationMetadataKey, "Session "+wire),
	)
	var out context.Context
	_, err := ic(
		inCtx,
		nil,
		&grpc.UnaryServerInfo{FullMethod: "/test/Method"},
		func(ctx context.Context, _ any) (any, error) {
			out = ctx
			return nil, nil
		},
	)
	if err != nil {
		t.Fatalf("SessionTokenInterceptor setup: %v", err)
	}
	return out
}

// mockSessionIssuer is a minimal SessionIssuer stub for tests.
type mockSessionIssuer struct {
	resolved issuer.ResolvedSession
	err      error
}

func (m *mockSessionIssuer) ResolveSessionToken(
	_ context.Context,
	_ string,
) (issuer.ResolvedSession, error) {
	return m.resolved, m.err
}

func (m *mockSessionIssuer) CreateSession(
	_ context.Context,
	_ uuid.UUID,
	_ session.SessionMetadata,
) (*sessionpb.AuthenticatedResult, error) {
	return nil, nil
}
func (m *mockSessionIssuer) RevokeSessionToken(_ context.Context, _ string) error { return nil }

func (m *mockSessionIssuer) ExtendSession(
	_ context.Context,
	_ string,
) (*sessionpb.SessionContext, error) {
	return nil, nil
}

func (m *mockSessionIssuer) AuthenticatedResultFromResolved(
	_ issuer.ResolvedSession,
) *sessionpb.AuthenticatedResult {
	return nil
}

func (m *mockSessionIssuer) AuthenticatedPrincipalFromResolved(
	_ issuer.ResolvedSession,
) *sessionpb.AuthenticatedPrincipal {
	return nil
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

func TestAuthnSessionPrincipalInterceptor_resolvesSession(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	iss := &mockSessionIssuer{
		resolved: issuer.ResolvedSession{
			UserID:    userID,
			SessionID: uuid.New(),
			IssuedAt:  time.Now(),
			ExpiresAt: time.Now().Add(time.Hour),
		},
	}

	ic := AuthnSessionPrincipalInterceptor(iss)
	wire := validWireToken(t)
	ctx := ctxWithHeaderToken(t, wire)
	info := &grpc.UnaryServerInfo{FullMethod: pb.AuthnService_RevokeSession_FullMethodName}

	_, err := ic(ctx, nil, info, func(ctx context.Context, _ any) (any, error) {
		resolved, ok := ResolvedSessionFromContext(ctx)
		if !ok {
			t.Fatal("expected resolved session in ctx")
		}
		if resolved.UserID != userID {
			t.Fatalf("userID: got %v want %v", resolved.UserID, userID)
		}
		return nil, nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAuthnSessionPrincipalInterceptor_missingToken(t *testing.T) {
	t.Parallel()

	ic := AuthnSessionPrincipalInterceptor(&mockSessionIssuer{})
	info := &grpc.UnaryServerInfo{FullMethod: pb.AuthnService_ExtendSession_FullMethodName}

	_, err := ic(context.Background(), nil, info, func(context.Context, any) (any, error) {
		t.Fatal("handler must not be called")
		return nil, nil
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("got %v, want Unauthenticated", status.Code(err))
	}
}

func TestCurrentAuthnSessionPrincipalInterceptorRejectsGatewayInternalOIDCAdminIdentity(t *testing.T) {
	t.Parallel()

	ctx := metadata.NewIncomingContext(
		context.Background(),
		metadata.Pairs("x-user-id", uuid.NewString()),
	)
	called := false
	_, err := AuthnSessionPrincipalInterceptor(&mockSessionIssuer{})(
		ctx,
		nil,
		&grpc.UnaryServerInfo{FullMethod: pb.OIDCClientAdminService_ListOIDCClients_FullMethodName},
		func(context.Context, any) (any, error) {
			called = true
			return nil, nil
		},
	)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("status code = %v, want Unauthenticated", status.Code(err))
	}
	if called {
		t.Fatal("OIDC admin handler ran without an opaque session token")
	}
}

func TestAuthnSessionPrincipalInterceptor_sessionExpired(t *testing.T) {
	t.Parallel()

	iss := &mockSessionIssuer{err: session.ErrSessionExpired}
	ic := AuthnSessionPrincipalInterceptor(iss)
	wire := validWireToken(t)
	ctx := ctxWithHeaderToken(t, wire)
	info := &grpc.UnaryServerInfo{
		FullMethod: pb.AuthnService_RevokeFederatedIdentity_FullMethodName,
	}

	_, err := ic(ctx, nil, info, func(context.Context, any) (any, error) {
		t.Fatal("handler must not be called for expired session")
		return nil, nil
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("got %v, want Unauthenticated", status.Code(err))
	}
	if !strings.Contains(status.Convert(err).Message(), "expired") {
		t.Fatalf("message: %q", status.Convert(err).Message())
	}
}

func TestAuthnSessionPrincipalInterceptor_unmappedRoute(t *testing.T) {
	t.Parallel()

	ic := AuthnSessionPrincipalInterceptor(&mockSessionIssuer{err: errors.New("should not call")})
	info := &grpc.UnaryServerInfo{FullMethod: pb.AuthnService_StartAuthSession_FullMethodName}

	called := false
	_, err := ic(context.Background(), nil, info, func(context.Context, any) (any, error) {
		called = true
		return nil, nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Fatal("handler must be called for unmapped routes")
	}
}
