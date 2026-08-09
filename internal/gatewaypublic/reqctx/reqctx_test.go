package reqctx

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/grpc/metadata"

	"sanzi.io/muid/pkg/gateway/httpmeta"
	grpcutils "sanzi.io/muid/pkg/grpc_utils"
)

func TestOutgoingAuthenticatedOverwritesInheritedIdentity(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs(
		httpmeta.UserIDKey, uuid.NewString(),
		httpmeta.UserIDKey, uuid.NewString(),
	))
	ctx = WithFacts(ctx, Facts{ClientIP: "203.0.113.7", GeoCountry: "TW"})
	ctx = OutgoingAuthenticated(ctx, userID)

	md, ok := metadata.FromOutgoingContext(ctx)
	if !ok {
		t.Fatal("expected outgoing metadata")
	}
	if got := md.Get(httpmeta.UserIDKey); len(got) != 1 || got[0] != userID.String() {
		t.Fatalf("user id metadata = %v", got)
	}
	if got := md.Get(httpmeta.ClientIPKey); len(got) != 1 || got[0] != "203.0.113.7" {
		t.Fatalf("client ip metadata = %v", got)
	}
}

func TestOutgoingMetadataRemovesInheritedIdentity(t *testing.T) {
	t.Parallel()

	ctx := metadata.NewOutgoingContext(
		context.Background(),
		metadata.Pairs(httpmeta.UserIDKey, uuid.NewString()),
	)
	ctx = OutgoingMetadata(ctx)
	md, ok := metadata.FromOutgoingContext(ctx)
	if !ok {
		t.Fatal("expected sanitized outgoing metadata")
	}
	if got := md.Get(httpmeta.UserIDKey); len(got) != 0 {
		t.Fatalf("user id metadata = %v, want removed", got)
	}
}

func TestOutgoingMetadataWithSessionOverwritesAuthorization(t *testing.T) {
	t.Parallel()

	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs(
		grpcutils.AuthorizationMetadataKey, "Bearer attacker",
		grpcutils.AuthorizationMetadataKey, "Session duplicate",
	))
	ctx = OutgoingMetadataWithSession(ctx, "trusted-token")
	md, ok := metadata.FromOutgoingContext(ctx)
	if !ok {
		t.Fatal("expected outgoing metadata")
	}
	want := "Session trusted-token"
	if got := md.Get(grpcutils.AuthorizationMetadataKey); len(got) != 1 || got[0] != want {
		t.Fatalf("authorization metadata = %v, want [%q]", got, want)
	}
}
