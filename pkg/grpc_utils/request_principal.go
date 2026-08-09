package grpcutils

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/url"
	"strings"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

const userIDMetadataKey = "x-user-id"

// WorkloadID identifies an mTLS-authenticated MUID workload.
type WorkloadID string

const (
	WorkloadGatewayPublic   WorkloadID = "gateway-public"
	WorkloadGatewayServices WorkloadID = "gateway-services"
	WorkloadGatewayInternal WorkloadID = "gateway-internal"
	WorkloadAuthn           WorkloadID = "authn"
	WorkloadAuthz           WorkloadID = "authz"
	WorkloadProfile         WorkloadID = "profile"
	WorkloadAdminIngress    WorkloadID = "admin-ingress"
)

// RequestPrincipal is the authenticated workload and, when present, the user
// identity forwarded by that workload.
type RequestPrincipal struct {
	Workload WorkloadID
	UserID   uuid.UUID
	HasUser  bool
}

// UserMode controls whether a method accepts forwarded user identity metadata.
type UserMode uint8

const (
	UserForbidden UserMode = iota
	UserOptional
	UserRequired
)

// MethodPrincipalPolicy defines the workloads and user identity mode accepted
// by one full gRPC method name.
type MethodPrincipalPolicy struct {
	Workloads map[WorkloadID]UserMode
}

type requestPrincipalContextKey struct{}

// RequestPrincipalFromContext returns the principal authenticated by
// NewRequestPrincipalInterceptor.
func RequestPrincipalFromContext(ctx context.Context) (RequestPrincipal, bool) {
	if ctx == nil {
		return RequestPrincipal{}, false
	}
	principal, ok := ctx.Value(requestPrincipalContextKey{}).(RequestPrincipal)
	return principal, ok
}

// WithRequestUserID attaches a nonzero authenticated user identity to ctx. If
// ctx already carries a workload principal, its workload is preserved.
func WithRequestUserID(ctx context.Context, userID uuid.UUID) context.Context {
	if ctx == nil || userID == uuid.Nil {
		return ctx
	}

	principal, _ := RequestPrincipalFromContext(ctx)
	principal.UserID = userID
	principal.HasUser = true
	return context.WithValue(ctx, requestPrincipalContextKey{}, principal)
}

// RequestUserIDFromContext returns the authenticated user identity attached to
// ctx, when one is present.
func RequestUserIDFromContext(ctx context.Context) (uuid.UUID, bool) {
	principal, ok := RequestPrincipalFromContext(ctx)
	if !ok || !principal.HasUser || principal.UserID == uuid.Nil {
		return uuid.Nil, false
	}
	return principal.UserID, true
}

// NewRequestPrincipalInterceptor constructs a fail-closed interceptor from
// exact full-method policies. The supplied policies are copied before use.
func NewRequestPrincipalInterceptor(
	policies map[string]MethodPrincipalPolicy,
) (grpc.UnaryServerInterceptor, error) {
	clonedPolicies, err := clonePrincipalPolicies(policies)
	if err != nil {
		return nil, err
	}

	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		policy, ok := clonedPolicies[info.FullMethod]
		if !ok {
			return nil, status.Error(codes.PermissionDenied, "method not permitted")
		}

		workload, err := verifiedWorkload(ctx)
		if err != nil {
			return nil, err
		}
		userMode, ok := policy.workloads[workload]
		if !ok {
			return nil, status.Error(codes.PermissionDenied, "workload not permitted")
		}

		principal, err := principalFromMetadata(ctx, userMode)
		if err != nil {
			return nil, err
		}
		principal.Workload = workload
		return handler(context.WithValue(ctx, requestPrincipalContextKey{}, principal), req)
	}, nil
}

type principalPolicy struct {
	workloads map[WorkloadID]UserMode
}

func clonePrincipalPolicies(policies map[string]MethodPrincipalPolicy) (map[string]principalPolicy, error) {
	if len(policies) == 0 {
		return nil, fmt.Errorf("grpcutils: request principal policies are empty")
	}

	cloned := make(map[string]principalPolicy, len(policies))
	for method, policy := range policies {
		if strings.TrimSpace(method) == "" {
			return nil, fmt.Errorf("grpcutils: request principal policy has empty method")
		}
		if len(policy.Workloads) == 0 {
			return nil, fmt.Errorf("grpcutils: request principal policy for %q has no workloads", method)
		}

		workloads := make(map[WorkloadID]UserMode, len(policy.Workloads))
		for workload, userMode := range policy.Workloads {
			if !validWorkload(workload) {
				return nil, fmt.Errorf("grpcutils: request principal policy for %q has invalid workload", method)
			}
			if !validUserMode(userMode) {
				return nil, fmt.Errorf("grpcutils: request principal policy for %q has invalid user mode", method)
			}
			workloads[workload] = userMode
		}
		cloned[method] = principalPolicy{workloads: workloads}
	}
	return cloned, nil
}

func validUserMode(mode UserMode) bool {
	return mode == UserForbidden || mode == UserOptional || mode == UserRequired
}

func verifiedWorkload(ctx context.Context) (WorkloadID, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "authentication required")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(tlsInfo.State.VerifiedChains) == 0 || len(tlsInfo.State.VerifiedChains[0]) == 0 {
		return "", status.Error(codes.Unauthenticated, "authentication required")
	}

	return workloadFromCertificate(tlsInfo.State.VerifiedChains[0][0])
}

func workloadFromCertificate(cert *x509.Certificate) (WorkloadID, error) {
	if cert == nil || len(cert.URIs) != 1 {
		return "", status.Error(codes.Unauthenticated, "authentication required")
	}
	workload, ok := workloadFromURI(cert.URIs[0])
	if !ok {
		return "", status.Error(codes.Unauthenticated, "authentication required")
	}
	return workload, nil
}

func workloadFromURI(uri *url.URL) (WorkloadID, bool) {
	if uri == nil || uri.Scheme != "spiffe" || uri.Host != "muid" || uri.User != nil || uri.Opaque != "" || uri.RawPath != "" || uri.RawQuery != "" || uri.Fragment != "" {
		return "", false
	}
	workload, found := strings.CutPrefix(uri.Path, "/service/")
	if !found || strings.Contains(workload, "/") || workload == "" {
		return "", false
	}
	id := WorkloadID(workload)
	return id, validWorkload(id)
}

func validWorkload(workload WorkloadID) bool {
	switch workload {
	case WorkloadGatewayPublic, WorkloadGatewayServices, WorkloadGatewayInternal,
		WorkloadAuthn, WorkloadAuthz, WorkloadProfile, WorkloadAdminIngress:
		return true
	default:
		return false
	}
}

func principalFromMetadata(ctx context.Context, mode UserMode) (RequestPrincipal, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	values := md.Get(userIDMetadataKey)
	if len(values) == 0 {
		if mode == UserRequired {
			return RequestPrincipal{}, status.Error(codes.Unauthenticated, "user identity required")
		}
		return RequestPrincipal{}, nil
	}
	if mode == UserForbidden {
		return RequestPrincipal{}, status.Error(codes.PermissionDenied, "user identity not permitted")
	}
	if len(values) != 1 {
		return RequestPrincipal{}, status.Error(codes.Unauthenticated, "user identity required")
	}

	userID, err := uuid.Parse(values[0])
	if err != nil || userID == uuid.Nil || userID.String() != values[0] {
		return RequestPrincipal{}, status.Error(codes.Unauthenticated, "user identity required")
	}
	return RequestPrincipal{UserID: userID, HasUser: true}, nil
}
