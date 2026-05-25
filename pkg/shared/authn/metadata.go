package authn

import (
	"context"
	"strings"

	"github.com/google/uuid"
	"google.golang.org/grpc/metadata"
)

const AuthenticatedUserIDMetadataKey = "x-authn-user-id"

// AuthenticatedUserIDFromMetadata returns the authenticated user id from incoming gRPC metadata.
func AuthenticatedUserIDFromMetadata(ctx context.Context) (string, bool) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", false
	}
	vals := md.Get(AuthenticatedUserIDMetadataKey)
	if len(vals) == 0 {
		return "", false
	}
	raw := strings.TrimSpace(vals[0])
	if raw == "" {
		return "", false
	}
	return raw, true
}

func authenticatedUserIDFromMetadata(ctx context.Context) (uuid.UUID, error) {
	raw, ok := AuthenticatedUserIDFromMetadata(ctx)
	if !ok {
		return uuid.Nil, GRPCMissingAuthenticatedPrincipal()
	}
	id, err := uuid.Parse(raw)
	if err != nil {
		return uuid.Nil, GRPCInvalidAuthenticatedPrincipal()
	}
	return id, nil
}
