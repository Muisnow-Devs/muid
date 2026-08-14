package authngrpc

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "sanzi.io/muid/api/proto/authn/v1"
	"sanzi.io/muid/internal/oidctoken"
	"sanzi.io/muid/internal/signature"
	grpcutils "sanzi.io/muid/pkg/grpc_utils"
)

type delegationVerifierFunc func(context.Context, string, string) (oidctoken.SessionAccessTokenClaims, error)

func (f delegationVerifierFunc) VerifySessionAccessToken(
	ctx context.Context,
	raw string,
	audience string,
) (oidctoken.SessionAccessTokenClaims, error) {
	return f(ctx, raw, audience)
}

func TestAccountDelegationInterceptorSuccessScrubsBearer(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	verifier := delegationVerifierFunc(func(_ context.Context, raw, audience string) (oidctoken.SessionAccessTokenClaims, error) {
		if raw != "raw.jwt.value" {
			t.Fatalf("raw token = %q", raw)
		}
		if audience != accountDelegationAudience {
			t.Fatalf("audience = %q", audience)
		}
		return oidctoken.SessionAccessTokenClaims{UserID: userID}, nil
	})
	ctx := grpcutils.WithRequestUserID(context.Background(), userID)
	ctx = metadata.NewIncomingContext(ctx, metadata.Pairs(
		grpcutils.AuthorizationMetadataKey, "Bearer raw.jwt.value",
		"x-trace-id", "trace",
	))
	handled := false
	info := &grpc.UnaryServerInfo{FullMethod: pb.AccountService_GetMyAccount_FullMethodName}
	_, err := AccountDelegationInterceptor(verifier)(ctx, &pb.GetMyAccountRequest{}, info,
		func(ctx context.Context, req any) (any, error) {
			return grpcutils.SessionTokenInterceptor()(ctx, req, info, func(ctx context.Context, _ any) (any, error) {
				handled = true
				md, _ := metadata.FromIncomingContext(ctx)
				if got := md.Get(grpcutils.AuthorizationMetadataKey); len(got) != 0 {
					t.Fatalf("authorization was not scrubbed: %v", got)
				}
				if got := md.Get("x-trace-id"); len(got) != 1 || got[0] != "trace" {
					t.Fatalf("other metadata = %v", md)
				}
				return nil, nil
			})
		},
	)
	if err != nil || !handled {
		t.Fatalf("interceptor = (handled %v, err %v)", handled, err)
	}
}

func TestAccountDelegationInterceptorRejectsInvalidRequests(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	validPrincipal := grpcutils.WithRequestUserID(context.Background(), userID)
	invalidToken := delegationVerifierFunc(func(context.Context, string, string) (oidctoken.SessionAccessTokenClaims, error) {
		return oidctoken.SessionAccessTokenClaims{}, oidctoken.ErrInvalidToken
	})
	backendFailure := delegationVerifierFunc(func(context.Context, string, string) (oidctoken.SessionAccessTokenClaims, error) {
		return oidctoken.SessionAccessTokenClaims{}, signature.ErrValidateFailed
	})
	canceled := delegationVerifierFunc(func(context.Context, string, string) (oidctoken.SessionAccessTokenClaims, error) {
		return oidctoken.SessionAccessTokenClaims{}, fmt.Errorf("verify token: %w", context.Canceled)
	})
	deadlineExceeded := delegationVerifierFunc(func(context.Context, string, string) (oidctoken.SessionAccessTokenClaims, error) {
		return oidctoken.SessionAccessTokenClaims{}, fmt.Errorf("verify token: %w", context.DeadlineExceeded)
	})
	mismatch := delegationVerifierFunc(func(context.Context, string, string) (oidctoken.SessionAccessTokenClaims, error) {
		return oidctoken.SessionAccessTokenClaims{UserID: uuid.New()}, nil
	})
	tests := []struct {
		name     string
		ctx      context.Context
		verifier accountDelegationVerifier
		want     codes.Code
	}{
		{name: "missing", ctx: validPrincipal, verifier: invalidToken, want: codes.Unauthenticated},
		{name: "wrong scheme", ctx: withAuthorization(validPrincipal, "Session token"), verifier: invalidToken, want: codes.Unauthenticated},
		{name: "malformed", ctx: withAuthorization(validPrincipal, "Bearer"), verifier: invalidToken, want: codes.Unauthenticated},
		{name: "duplicates", ctx: metadata.NewIncomingContext(validPrincipal, metadata.Pairs("authorization", "Bearer one", "authorization", "Bearer two")), verifier: invalidToken, want: codes.Unauthenticated},
		{name: "missing principal", ctx: withAuthorization(context.Background(), "Bearer token"), verifier: invalidToken, want: codes.Unauthenticated},
		{name: "wrong audience or invalid token", ctx: withAuthorization(validPrincipal, "Bearer token"), verifier: invalidToken, want: codes.Unauthenticated},
		{name: "nil verifier", ctx: withAuthorization(validPrincipal, "Bearer token"), want: codes.Unavailable},
		{name: "verifier config failure", ctx: withAuthorization(validPrincipal, "Bearer token"), verifier: delegationVerifierFunc(func(context.Context, string, string) (oidctoken.SessionAccessTokenClaims, error) {
			return oidctoken.SessionAccessTokenClaims{}, signature.ErrInvalidConfig
		}), want: codes.Unavailable},
		{name: "verifier backend failure", ctx: withAuthorization(validPrincipal, "Bearer token"), verifier: backendFailure, want: codes.Unavailable},
		{name: "verifier canceled", ctx: withAuthorization(validPrincipal, "Bearer token"), verifier: canceled, want: codes.Canceled},
		{name: "verifier deadline exceeded", ctx: withAuthorization(validPrincipal, "Bearer token"), verifier: deadlineExceeded, want: codes.DeadlineExceeded},
		{name: "subject mismatch", ctx: withAuthorization(validPrincipal, "Bearer token"), verifier: mismatch, want: codes.PermissionDenied},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			handled := false
			_, err := AccountDelegationInterceptor(tc.verifier)(tc.ctx, nil, &grpc.UnaryServerInfo{
				FullMethod: pb.AccountService_GetMyAccount_FullMethodName,
			}, func(context.Context, any) (any, error) {
				handled = true
				return nil, errors.New("unexpected handler")
			})
			if handled || status.Code(err) != tc.want {
				t.Fatalf("result = (handled %v, code %v), want (false, %v)", handled, status.Code(err), tc.want)
			}
		})
	}
}

func TestAccountDelegationInterceptorOtherMethodIsNoOp(t *testing.T) {
	t.Parallel()

	ctx := withAuthorization(context.Background(), "Session opaque-token")
	called := false
	_, err := AccountDelegationInterceptor(delegationVerifierFunc(
		func(context.Context, string, string) (oidctoken.SessionAccessTokenClaims, error) {
			t.Fatal("verifier called for non-account method")
			return oidctoken.SessionAccessTokenClaims{}, nil
		},
	))(ctx, nil, &grpc.UnaryServerInfo{FullMethod: pb.SessionService_GetSessionPrincipal_FullMethodName}, func(ctx context.Context, _ any) (any, error) {
		called = true
		md, _ := metadata.FromIncomingContext(ctx)
		if got := md.Get(grpcutils.AuthorizationMetadataKey); len(got) != 1 || got[0] != "Session opaque-token" {
			t.Fatalf("authorization changed: %v", got)
		}
		return nil, nil
	})
	if err != nil || !called {
		t.Fatalf("interceptor = (called %v, err %v)", called, err)
	}
}

func TestAccountDelegationInterceptorFutureAccountMethodIsProtected(t *testing.T) {
	t.Parallel()

	const futureMethod = accountServiceMethodPrefix + "FutureMethod"
	userID := uuid.New()
	principal := grpcutils.WithRequestUserID(context.Background(), userID)
	invalid := delegationVerifierFunc(func(context.Context, string, string) (oidctoken.SessionAccessTokenClaims, error) {
		return oidctoken.SessionAccessTokenClaims{}, oidctoken.ErrInvalidToken
	})
	valid := delegationVerifierFunc(func(context.Context, string, string) (oidctoken.SessionAccessTokenClaims, error) {
		return oidctoken.SessionAccessTokenClaims{UserID: userID}, nil
	})
	tests := []struct {
		name     string
		ctx      context.Context
		verifier accountDelegationVerifier
		wantCode codes.Code
		wantCall bool
	}{
		{name: "missing delegation", ctx: principal, verifier: invalid, wantCode: codes.Unauthenticated},
		{name: "invalid delegation", ctx: withAuthorization(principal, "Bearer invalid"), verifier: invalid, wantCode: codes.Unauthenticated},
		{name: "valid delegation", ctx: withAuthorization(principal, "Bearer valid"), verifier: valid, wantCode: codes.OK, wantCall: true},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			called := false
			_, err := AccountDelegationInterceptor(tc.verifier)(tc.ctx, nil, &grpc.UnaryServerInfo{
				FullMethod: futureMethod,
			}, func(context.Context, any) (any, error) {
				called = true
				return nil, nil
			})
			if got := status.Code(err); got != tc.wantCode {
				t.Fatalf("code = %v, want %v", got, tc.wantCode)
			}
			if called != tc.wantCall {
				t.Fatalf("handler called = %v, want %v", called, tc.wantCall)
			}
		})
	}
}

func TestAccountDelegationInterceptorAdjacentServiceIsNoOp(t *testing.T) {
	t.Parallel()

	called := false
	_, err := AccountDelegationInterceptor(nil)(context.Background(), nil, &grpc.UnaryServerInfo{
		FullMethod: "/muid.authn.v1.AccountServiceAdmin/FutureMethod",
	}, func(context.Context, any) (any, error) {
		called = true
		return nil, nil
	})
	if err != nil || !called {
		t.Fatalf("interceptor = (called %v, err %v), want no-op", called, err)
	}
}

func withAuthorization(ctx context.Context, value string) context.Context {
	return metadata.NewIncomingContext(ctx, metadata.Pairs(grpcutils.AuthorizationMetadataKey, value))
}
