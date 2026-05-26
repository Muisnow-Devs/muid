package account

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"sanzi.io/muid/internal/authn/ent"
	"sanzi.io/muid/internal/authn/ent/userfederatedidentity"
)

func federatedSvc(t *testing.T) (*federatedService, *ent.Client) {
	t.Helper()
	client := openSessionTestDB(t)
	return &federatedService{store: &Store{DB: client}}, client
}

func linkParams(userID uuid.UUID, provider, subject, email string) FederatedLinkParams {
	return FederatedLinkParams{
		UserID:        userID,
		Provider:      provider,
		Subject:       subject,
		Email:         email,
		EmailVerified: true,
	}
}

func TestRevokeFederatedIdentity_success(t *testing.T) {
	t.Parallel()

	svc, client := federatedSvc(t)
	ctx := context.Background()
	userID := uuid.MustParse("550e8400-e29b-41d4-a716-446655440001")
	seedUserRef(t, client, userID)

	err := client.UserFederatedIdentity.Create().
		SetUserID(userID).
		SetProvider("google").
		SetSubject("sub-1").
		Exec(ctx)
	if err != nil {
		t.Fatalf("seed federated: %v", err)
	}

	err = svc.RevokeFederatedIdentity(ctx, userID, "Google")
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}

	row, err := client.UserFederatedIdentity.Query().
		Where(
			userfederatedidentity.UserIDEQ(userID),
			userfederatedidentity.ProviderEQ("google"),
		).
		Only(ctx)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if row.RevokedAt.IsZero() {
		t.Fatal("expected revoked_at to be set")
	}
}

func TestRevokeFederatedIdentity_notFound(t *testing.T) {
	t.Parallel()

	svc, client := federatedSvc(t)
	ctx := context.Background()
	userID := uuid.MustParse("550e8400-e29b-41d4-a716-446655440002")
	seedUserRef(t, client, userID)

	err := svc.RevokeFederatedIdentity(ctx, userID, "google")
	if err != ErrFederatedIdentityNotFound {
		t.Fatalf("got %v want %v", err, ErrFederatedIdentityNotFound)
	}
}

func TestRevokeFederatedIdentity_alreadyRevoked(t *testing.T) {
	t.Parallel()

	svc, client := federatedSvc(t)
	ctx := context.Background()
	userID := uuid.MustParse("550e8400-e29b-41d4-a716-446655440003")
	seedUserRef(t, client, userID)

	err := client.UserFederatedIdentity.Create().
		SetUserID(userID).
		SetProvider("google").
		SetSubject("sub-2").
		SetRevokedAt(time.Now()).
		Exec(ctx)
	if err != nil {
		t.Fatalf("seed federated: %v", err)
	}

	err = svc.RevokeFederatedIdentity(ctx, userID, "google")
	if err != ErrFederatedIdentityNotFound {
		t.Fatalf("got %v want %v", err, ErrFederatedIdentityNotFound)
	}
}

func TestFederatedIdentity_revokeBlocksLoginThenRelink(t *testing.T) {
	t.Parallel()

	svc, client := federatedSvc(t)
	oidc := &oidcService{store: svc.store}
	ctx := context.Background()
	userID := uuid.MustParse("550e8400-e29b-41d4-a716-446655440010")
	seedUserRef(t, client, userID)

	err := svc.LinkFederatedIdentity(
		ctx,
		linkParams(userID, "google", "sub-login", "u@example.com"),
	)
	if err != nil {
		t.Fatalf("link: %v", err)
	}

	got, reg, err := oidc.LookupOIDCLogin(ctx, "google", "sub-login", "u@example.com", true, "", "")
	if err != nil || reg != nil || got != userID {
		t.Fatalf("before revoke: user=%v reg=%v err=%v", got, reg, err)
	}

	err = svc.RevokeFederatedIdentity(ctx, userID, "google")
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}

	got, reg, err = oidc.LookupOIDCLogin(ctx, "google", "sub-login", "u@example.com", true, "", "")
	if err != nil {
		t.Fatalf("after revoke lookup err: %v", err)
	}
	if got != uuid.Nil {
		t.Fatalf("revoked subject must not resolve to user, got %v", got)
	}
	if reg == nil {
		t.Fatal("expected register-required after revoke")
	}

	err = svc.LinkFederatedIdentity(ctx, linkParams(userID, "google", "sub-login", "u@example.com"))
	if err != nil {
		t.Fatalf("re-link: %v", err)
	}

	got, reg, err = oidc.LookupOIDCLogin(ctx, "google", "sub-login", "u@example.com", true, "", "")
	if err != nil || reg != nil || got != userID {
		t.Fatalf("after re-link: user=%v reg=%v err=%v", got, reg, err)
	}

	n, err := client.UserFederatedIdentity.Query().Count(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expected single federated row, got %d", n)
	}
}

func TestLinkFederatedIdentity_crossUserActiveFails(t *testing.T) {
	t.Parallel()

	svc, client := federatedSvc(t)
	ctx := context.Background()
	owner := uuid.MustParse("550e8400-e29b-41d4-a716-446655440020")
	other := uuid.MustParse("6ba7b810-9dad-11d1-80b4-00c04fd430c8")
	seedUserRef(t, client, owner)
	seedUserRef(t, client, other)

	err := svc.LinkFederatedIdentity(ctx, linkParams(owner, "google", "sub-shared", "a@b.com"))
	if err != nil {
		t.Fatalf("owner link: %v", err)
	}

	err = svc.LinkFederatedIdentity(ctx, linkParams(other, "google", "sub-shared", "c@d.com"))
	if !errors.Is(err, ErrFederatedSubjectLinkedToOtherUser) {
		t.Fatalf("got %v want %v", err, ErrFederatedSubjectLinkedToOtherUser)
	}
}

func TestLinkFederatedIdentity_crossUserRevokedStillFails(t *testing.T) {
	t.Parallel()

	svc, client := federatedSvc(t)
	ctx := context.Background()
	owner := uuid.MustParse("550e8400-e29b-41d4-a716-446655440021")
	other := uuid.MustParse("6ba7b810-9dad-11d1-80b4-00c04fd430c9")
	seedUserRef(t, client, owner)
	seedUserRef(t, client, other)

	err := svc.LinkFederatedIdentity(ctx, linkParams(owner, "google", "sub-revoked", "a@b.com"))
	if err != nil {
		t.Fatalf("owner link: %v", err)
	}
	err = svc.RevokeFederatedIdentity(ctx, owner, "google")
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}

	err = svc.LinkFederatedIdentity(ctx, linkParams(other, "google", "sub-revoked", "c@d.com"))
	if !errors.Is(err, ErrFederatedSubjectLinkedToOtherUser) {
		t.Fatalf("got %v want %v", err, ErrFederatedSubjectLinkedToOtherUser)
	}
}

func TestLinkFederatedIdentity_idempotentActive(t *testing.T) {
	t.Parallel()

	svc, client := federatedSvc(t)
	ctx := context.Background()
	userID := uuid.MustParse("550e8400-e29b-41d4-a716-446655440030")
	seedUserRef(t, client, userID)

	p := linkParams(userID, "google", "sub-idem", "x@y.z")
	err := svc.LinkFederatedIdentity(ctx, p)
	if err != nil {
		t.Fatalf("first link: %v", err)
	}
	err = svc.LinkFederatedIdentity(ctx, p)
	if err != nil {
		t.Fatalf("second link: %v", err)
	}

	n, err := client.UserFederatedIdentity.Query().Count(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("rows: %d", n)
	}
}
