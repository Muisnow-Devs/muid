package policy

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"

	"sanzi.io/muid/internal/authn/ent/enttest"
)

func TestEntLinkPolicy_ValidateLink(t *testing.T) {
	t.Parallel()

	client := enttest.Open(t, "sqlite3", "file:entpolicy?mode=memory&cache=shared&_fk=1")
	defer client.Close()

	ctx := context.Background()
	p := NewEntLinkPolicy(client)

	user1 := uuid.New()

	// Insert UserRef to satisfy foreign key constraints
	err := client.UserRef.Create().SetID(user1).SetEmail("user1@example.com").Exec(ctx)
	if err != nil {
		t.Fatalf("failed to create user1 ref: %v", err)
	}

	// 1. Validate on non-existent identity -> ALLOW
	decision, err := p.ValidateLink(ctx, LinkRequest{
		Provider: "google",
		Subject:  "sub-1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision != LinkDecisionAllow {
		t.Errorf("expected ALLOW, got %v", decision)
	}

	// Create identity linked to user 1
	identityRecord, err := client.UserIdentity.Create().
		SetUserID(user1).
		SetProvider("google").
		SetSubject("sub-1").
		Save(ctx)
	if err != nil {
		t.Fatalf("failed to create identity: %v", err)
	}

	// 2. Validate same identity linked to same user -> REJECT (identity slot is taken)
	decision, err = p.ValidateLink(ctx, LinkRequest{
		Provider: "google",
		Subject:  "sub-1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision != LinkDecisionReject {
		t.Errorf("expected REJECT, got %v", decision)
	}

	// 3. Validate same identity linked to different user -> REJECT
	decision, err = p.ValidateLink(ctx, LinkRequest{
		Provider: "google",
		Subject:  "sub-1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision != LinkDecisionReject {
		t.Errorf("expected REJECT, got %v", decision)
	}

	// 4. Revoke the identity
	_, err = client.UserIdentity.UpdateOne(identityRecord).
		SetRevokedAt(time.Now()).
		Save(ctx)
	if err != nil {
		t.Fatalf("failed to revoke identity: %v", err)
	}

	// 5. Validate revoked identity -> ALLOW (slot released)
	decision, err = p.ValidateLink(ctx, LinkRequest{
		Provider: "google",
		Subject:  "sub-1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision != LinkDecisionAllow {
		t.Errorf("expected ALLOW, got %v", decision)
	}
}
