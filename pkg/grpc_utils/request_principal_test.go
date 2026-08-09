package grpcutils

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/url"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

const principalTestMethod = "/muid.test.v1.TestService/Method"

func TestRequestPrincipalInterceptor(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	interceptor := mustPrincipalInterceptor(t, map[string]MethodPrincipalPolicy{
		principalTestMethod: {
			Workloads: map[WorkloadID]UserMode{WorkloadGatewayPublic: UserRequired},
		},
	})

	ctx := principalContext(t, WorkloadGatewayPublic)
	ctx = metadata.NewIncomingContext(ctx, metadata.Pairs(userIDMetadataKey, userID.String()))
	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: principalTestMethod}, func(ctx context.Context, _ any) (any, error) {
		principal, ok := RequestPrincipalFromContext(ctx)
		if !ok {
			t.Error("RequestPrincipalFromContext returned no principal")
			return nil, nil
		}
		if principal.Workload != WorkloadGatewayPublic {
			t.Errorf("principal workload = %q, want %q", principal.Workload, WorkloadGatewayPublic)
		}
		if !principal.HasUser || principal.UserID != userID {
			t.Errorf("principal user = (%v, %v), want (%v, true)", principal.UserID, principal.HasUser, userID)
		}
		return nil, nil
	})
	if err != nil {
		t.Fatalf("interceptor: %v", err)
	}
}

func TestRequestPrincipalInterceptorUsesPerWorkloadUserMode(t *testing.T) {
	t.Parallel()

	interceptor := mustPrincipalInterceptor(t, map[string]MethodPrincipalPolicy{
		principalTestMethod: {
			Workloads: map[WorkloadID]UserMode{
				WorkloadAuthn:           UserOptional,
				WorkloadGatewayServices: UserRequired,
			},
		},
	})

	_, err := interceptor(
		principalContext(t, WorkloadAuthn),
		nil,
		&grpc.UnaryServerInfo{FullMethod: principalTestMethod},
		allowPrincipalRequest,
	)
	if err != nil {
		t.Fatalf("optional workload without user: %v", err)
	}

	_, err = interceptor(
		principalContext(t, WorkloadGatewayServices),
		nil,
		&grpc.UnaryServerInfo{FullMethod: principalTestMethod},
		allowPrincipalRequest,
	)
	if got := status.Code(err); got != codes.Unauthenticated {
		t.Fatalf("required workload without user code = %v, want %v", got, codes.Unauthenticated)
	}
}

func TestRequestUserIDContextHelpers(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	workload := WorkloadGatewayPublic
	ctx := context.WithValue(context.Background(), requestPrincipalContextKey{}, RequestPrincipal{
		Workload: workload,
	})
	ctx = WithRequestUserID(ctx, userID)

	principal, ok := RequestPrincipalFromContext(ctx)
	if !ok {
		t.Fatal("RequestPrincipalFromContext returned no principal")
	}
	if principal.Workload != workload {
		t.Errorf("workload = %q, want %q", principal.Workload, workload)
	}
	if !principal.HasUser || principal.UserID != userID {
		t.Errorf("principal user = (%v, %v), want (%v, true)", principal.UserID, principal.HasUser, userID)
	}

	got, ok := RequestUserIDFromContext(ctx)
	if !ok || got != userID {
		t.Errorf("RequestUserIDFromContext = (%v, %v), want (%v, true)", got, ok, userID)
	}
	if _, ok := RequestUserIDFromContext(context.Background()); ok {
		t.Error("RequestUserIDFromContext unexpectedly found an absent user")
	}

	withoutUser := WithRequestUserID(context.Background(), uuid.Nil)
	if withoutUser == nil {
		t.Fatal("WithRequestUserID returned nil context")
	}
	if _, ok := RequestUserIDFromContext(withoutUser); ok {
		t.Error("RequestUserIDFromContext unexpectedly found a zero user")
	}
}

func TestRequestPrincipalInterceptorRejectsInvalidRequests(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	tests := []struct {
		name     string
		policy   MethodPrincipalPolicy
		method   string
		ctx      context.Context
		wantCode codes.Code
	}{
		{
			name:     "unknown method",
			policy:   MethodPrincipalPolicy{Workloads: map[WorkloadID]UserMode{WorkloadGatewayPublic: UserOptional}},
			method:   "unknown",
			ctx:      principalContext(t, WorkloadGatewayPublic),
			wantCode: codes.PermissionDenied,
		},
		{
			name:     "missing TLS peer",
			policy:   MethodPrincipalPolicy{Workloads: map[WorkloadID]UserMode{WorkloadGatewayPublic: UserOptional}},
			method:   principalTestMethod,
			ctx:      context.Background(),
			wantCode: codes.Unauthenticated,
		},
		{
			name:     "disallowed workload",
			policy:   MethodPrincipalPolicy{Workloads: map[WorkloadID]UserMode{WorkloadGatewayPublic: UserOptional}},
			method:   principalTestMethod,
			ctx:      principalContext(t, WorkloadAuthn),
			wantCode: codes.PermissionDenied,
		},
		{
			name:     "required user missing",
			policy:   MethodPrincipalPolicy{Workloads: map[WorkloadID]UserMode{WorkloadGatewayPublic: UserRequired}},
			method:   principalTestMethod,
			ctx:      principalContext(t, WorkloadGatewayPublic),
			wantCode: codes.Unauthenticated,
		},
		{
			name:     "forbidden user present",
			policy:   MethodPrincipalPolicy{Workloads: map[WorkloadID]UserMode{WorkloadGatewayPublic: UserForbidden}},
			method:   principalTestMethod,
			ctx:      metadata.NewIncomingContext(principalContext(t, WorkloadGatewayPublic), metadata.Pairs(userIDMetadataKey, userID.String())),
			wantCode: codes.PermissionDenied,
		},
		{
			name:     "noncanonical user",
			policy:   MethodPrincipalPolicy{Workloads: map[WorkloadID]UserMode{WorkloadGatewayPublic: UserRequired}},
			method:   principalTestMethod,
			ctx:      metadata.NewIncomingContext(principalContext(t, WorkloadGatewayPublic), metadata.Pairs(userIDMetadataKey, userID.String()[0:8])),
			wantCode: codes.Unauthenticated,
		},
		{
			name:     "duplicate user",
			policy:   MethodPrincipalPolicy{Workloads: map[WorkloadID]UserMode{WorkloadGatewayPublic: UserOptional}},
			method:   principalTestMethod,
			ctx:      metadata.NewIncomingContext(principalContext(t, WorkloadGatewayPublic), metadata.Pairs(userIDMetadataKey, userID.String(), userIDMetadataKey, userID.String())),
			wantCode: codes.Unauthenticated,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			interceptor := mustPrincipalInterceptor(t, map[string]MethodPrincipalPolicy{principalTestMethod: test.policy})
			_, err := interceptor(test.ctx, nil, &grpc.UnaryServerInfo{FullMethod: test.method}, allowPrincipalRequest)
			if got := status.Code(err); got != test.wantCode {
				t.Errorf("status.Code() = %v, want %v", got, test.wantCode)
			}
		})
	}
}

func TestRequestPrincipalInterceptorRejectsInvalidWorkloadURI(t *testing.T) {
	t.Parallel()

	interceptor := mustPrincipalInterceptor(t, map[string]MethodPrincipalPolicy{
		principalTestMethod: {Workloads: map[WorkloadID]UserMode{WorkloadGatewayPublic: UserOptional}},
	})
	ctx := principalContextForURIs(t, "spiffe://muid/service/gateway-public", "spiffe://muid/service/authn")
	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: principalTestMethod}, allowPrincipalRequest)
	if got := status.Code(err); got != codes.Unauthenticated {
		t.Errorf("status.Code() = %v, want %v", got, codes.Unauthenticated)
	}
}

func TestNewRequestPrincipalInterceptorCopiesPolicies(t *testing.T) {
	t.Parallel()

	workloads := map[WorkloadID]UserMode{WorkloadGatewayPublic: UserOptional}
	policies := map[string]MethodPrincipalPolicy{
		principalTestMethod: {Workloads: workloads},
	}
	interceptor := mustPrincipalInterceptor(t, policies)
	delete(workloads, WorkloadGatewayPublic)
	workloads[WorkloadAuthn] = UserForbidden
	policies[principalTestMethod] = MethodPrincipalPolicy{Workloads: map[WorkloadID]UserMode{WorkloadAuthn: UserForbidden}}

	_, err := interceptor(principalContext(t, WorkloadGatewayPublic), nil, &grpc.UnaryServerInfo{FullMethod: principalTestMethod}, allowPrincipalRequest)
	if err != nil {
		t.Fatalf("interceptor after policy mutation: %v", err)
	}
}

func TestNewRequestPrincipalInterceptorRejectsInvalidPolicies(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		policies map[string]MethodPrincipalPolicy
	}{
		{name: "empty", policies: nil},
		{name: "empty method", policies: map[string]MethodPrincipalPolicy{" ": {Workloads: map[WorkloadID]UserMode{WorkloadAuthn: UserOptional}}}},
		{name: "no workloads", policies: map[string]MethodPrincipalPolicy{"/method": {}}},
		{name: "unknown workload", policies: map[string]MethodPrincipalPolicy{"/method": {Workloads: map[WorkloadID]UserMode{"unknown": UserOptional}}}},
		{name: "invalid user mode", policies: map[string]MethodPrincipalPolicy{"/method": {Workloads: map[WorkloadID]UserMode{WorkloadAuthn: UserMode(99)}}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewRequestPrincipalInterceptor(test.policies); err == nil {
				t.Fatal("NewRequestPrincipalInterceptor succeeded")
			}
		})
	}
}

func mustPrincipalInterceptor(t *testing.T, policies map[string]MethodPrincipalPolicy) grpc.UnaryServerInterceptor {
	t.Helper()
	interceptor, err := NewRequestPrincipalInterceptor(policies)
	if err != nil {
		t.Fatalf("NewRequestPrincipalInterceptor: %v", err)
	}
	return interceptor
}

func principalContext(t *testing.T, workload WorkloadID) context.Context {
	t.Helper()
	return principalContextForURIs(t, "spiffe://muid/service/"+string(workload))
}

func principalContextForURIs(t *testing.T, values ...string) context.Context {
	t.Helper()
	uris := make([]*url.URL, 0, len(values))
	for _, value := range values {
		uri, err := url.Parse(value)
		if err != nil {
			t.Fatalf("url.Parse(%q): %v", value, err)
		}
		uris = append(uris, uri)
	}
	leaf := &x509.Certificate{URIs: uris}
	tlsInfo := credentials.TLSInfo{State: tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{leaf}}}}
	return peer.NewContext(context.Background(), &peer.Peer{AuthInfo: tlsInfo})
}

func allowPrincipalRequest(context.Context, any) (any, error) {
	return nil, nil
}
