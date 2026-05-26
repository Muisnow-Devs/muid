package account

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"sanzi.io/muid/internal/authn/ent"
)

func oidcSvc(t *testing.T) (*oidcService, *ent.Client) {
	t.Helper()
	client := openSessionTestDB(t)
	return &oidcService{store: &Store{DB: client}}, client
}

func seedUserRefEmail(t *testing.T, client *ent.Client, userID uuid.UUID, email string) {
	t.Helper()
	ctx := context.Background()
	err := client.UserRef.Create().
		SetID(userID).
		SetEmail(email).
		Exec(ctx)
	if err != nil {
		t.Fatalf("seed user ref: %v", err)
	}
}

func TestLookupOIDCLogin_registerRequiredWhenEmailRegistered(t *testing.T) {
	t.Parallel()

	oidc, client := oidcSvc(t)
	ctx := context.Background()
	userID := uuid.MustParse("550e8400-e29b-41d4-a716-446655440030")
	seedUserRefEmail(t, client, userID, "link@example.com")

	got, reg, err := oidc.LookupOIDCLogin(
		ctx,
		"google",
		"sub-new",
		"link@example.com",
		true,
		"",
		"",
	)
	if err != nil {
		t.Fatalf("LookupOIDCLogin: %v", err)
	}
	if got != uuid.Nil {
		t.Fatalf("user id: got %v want nil", got)
	}
	if reg == nil || reg.Identity.GetEmail() != "link@example.com" {
		t.Fatalf("register required: %+v", reg)
	}
}

func TestLookupOIDCFederatedUser_alreadyLinked(t *testing.T) {
	t.Parallel()

	oidc, client := oidcSvc(t)
	fed := &federatedService{store: oidc.store}
	ctx := context.Background()
	userID := uuid.MustParse("550e8400-e29b-41d4-a716-446655440031")
	seedUserRefEmail(t, client, userID, "linked@example.com")

	err := fed.LinkFederatedIdentity(
		ctx,
		linkParams(userID, "google", "sub-linked", "linked@example.com"),
	)
	if err != nil {
		t.Fatalf("link: %v", err)
	}

	got, found, err := oidc.LookupOIDCFederatedUser(ctx, "google", "sub-linked")
	if err != nil || !found || got != userID {
		t.Fatalf("lookup: user=%v found=%v err=%v", got, found, err)
	}
}

func TestLookupOIDCFederatedUser_subjectLinkedToOtherUser(t *testing.T) {
	t.Parallel()

	oidc, client := oidcSvc(t)
	fed := &federatedService{store: oidc.store}
	ctx := context.Background()
	owner := uuid.MustParse("550e8400-e29b-41d4-a716-446655440032")
	seedUserRefEmail(t, client, owner, "owner@example.com")

	err := fed.LinkFederatedIdentity(
		ctx,
		linkParams(owner, "google", "sub-taken", "owner@example.com"),
	)
	if err != nil {
		t.Fatalf("owner link: %v", err)
	}

	got, found, err := oidc.LookupOIDCFederatedUser(ctx, "google", "sub-taken")
	if err != nil || !found || got != owner {
		t.Fatalf("lookup: user=%v found=%v err=%v", got, found, err)
	}
}
