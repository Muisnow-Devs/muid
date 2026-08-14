package authn

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestEnrichRequiredAuthenticatedUser(t *testing.T) {
	t.Parallel()

	id := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
	ctx := WithAuthenticatedUserID(context.Background(), id)

	enriched, got, err := EnrichRequiredAuthenticatedUser(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != id {
		t.Fatalf("id: got %v want %v", got, id)
	}
	stored, ok := AuthenticatedUserIDFromContext(enriched)
	if !ok || stored != id {
		t.Fatalf("context id: got %v ok=%v", stored, ok)
	}
}

func TestEnrichRequiredAuthenticatedUser_missingPrincipal(t *testing.T) {
	t.Parallel()

	_, _, err := EnrichRequiredAuthenticatedUser(context.Background())
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("code: got %v want Unauthenticated", status.Code(err))
	}
	if status.Convert(err).Message() != MsgMissingAuthenticatedPrincipal {
		t.Fatalf("message: got %q", status.Convert(err).Message())
	}
}

func TestRequiredAuthenticatedUserIDFromContext_missing(t *testing.T) {
	t.Parallel()

	_, err := RequiredAuthenticatedUserIDFromContext(context.Background())
	if status.Code(err) != codes.Internal {
		t.Fatalf("code: got %v want Internal", status.Code(err))
	}
	if status.Convert(err).Message() != MsgMissingAuthenticatedUserIDContext {
		t.Fatalf("message: got %q", status.Convert(err).Message())
	}
}

func TestAuthenticatedUserIDContextHelpers_ignoreZeroID(t *testing.T) {
	t.Parallel()

	ctx := WithAuthenticatedUserID(context.Background(), uuid.Nil)
	if _, ok := AuthenticatedUserIDFromContext(ctx); ok {
		t.Fatal("AuthenticatedUserIDFromContext unexpectedly found a zero user")
	}

	_, err := RequiredAuthenticatedUserIDFromContext(ctx)
	if status.Code(err) != codes.Internal {
		t.Fatalf("code: got %v want Internal", status.Code(err))
	}
	if status.Convert(err).Message() != MsgMissingAuthenticatedUserIDContext {
		t.Fatalf("message: got %q", status.Convert(err).Message())
	}
}
