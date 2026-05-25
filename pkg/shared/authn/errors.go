package authn

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	// MsgMissingAuthenticatedPrincipal is returned when x-authn-user-id metadata is absent.
	MsgMissingAuthenticatedPrincipal = "authenticated principal required"
	// MsgInvalidAuthenticatedPrincipal is returned when x-authn-user-id metadata is not a UUID.
	MsgInvalidAuthenticatedPrincipal = "invalid authenticated principal"
	// MsgMissingAuthenticatedUserIDContext is returned when handlers require an id not set by middleware.
	MsgMissingAuthenticatedUserIDContext = "missing authenticated user id in context"
)

// GRPCMissingAuthenticatedPrincipal reports missing authenticated principal metadata.
func GRPCMissingAuthenticatedPrincipal() error {
	return status.Error(codes.InvalidArgument, MsgMissingAuthenticatedPrincipal)
}

// GRPCInvalidAuthenticatedPrincipal reports malformed authenticated principal metadata.
func GRPCInvalidAuthenticatedPrincipal() error {
	return status.Error(codes.InvalidArgument, MsgInvalidAuthenticatedPrincipal)
}

// GRPCMissingAuthenticatedUserIDContext reports a missing enriched user id on context.
func GRPCMissingAuthenticatedUserIDContext() error {
	return status.Error(codes.Internal, MsgMissingAuthenticatedUserIDContext)
}
