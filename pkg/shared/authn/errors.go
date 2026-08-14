package authn

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	// MsgMissingAuthenticatedPrincipal is returned when the verified request principal has no user.
	MsgMissingAuthenticatedPrincipal = "authenticated principal required"
	// MsgMissingAuthenticatedUserIDContext is returned when handlers require an id not set by middleware.
	MsgMissingAuthenticatedUserIDContext = "missing authenticated user id in context"
)

// GRPCMissingAuthenticatedPrincipal reports a missing authenticated user on the verified principal.
func GRPCMissingAuthenticatedPrincipal() error {
	return status.Error(codes.Unauthenticated, MsgMissingAuthenticatedPrincipal)
}

// GRPCMissingAuthenticatedUserIDContext reports a missing enriched user id on context.
func GRPCMissingAuthenticatedUserIDContext() error {
	return status.Error(codes.Internal, MsgMissingAuthenticatedUserIDContext)
}
