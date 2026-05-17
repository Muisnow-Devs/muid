package identity

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"entgo.io/ent/dialect"
	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	claimspb "sanzi.io/muid/api/proto/shared/v1/claims"
	"sanzi.io/muid/internal/authn/ent"
	"sanzi.io/muid/internal/authn/ent/enttest"
	idn "sanzi.io/muid/internal/identity"
	"sanzi.io/muid/internal/session"
	"sanzi.io/muid/infra/mocked"
	authnkv "sanzi.io/muid/internal/authn/infra/kv"
)

func openRegisterFinishTestDB(t *testing.T) *ent.Client {
	t.Helper()
	dsn := fmt.Sprintf(
		"file:%s?mode=memory&cache=shared&_fk=1",
		strings.ReplaceAll(t.Name(), "/", "_"),
	)
	return enttest.Open(t, dialect.SQLite, dsn)
}

func seedRegisterFinishUserRef(t *testing.T, client *ent.Client, userID uuid.UUID, email string) {
	t.Helper()
	err := client.UserRef.Create().
		SetID(userID).
		SetEmail(email).
		Exec(context.Background())
	if err != nil {
		t.Fatalf("seed user ref: %v", err)
	}
}

func TestFinishRegisterRequested(t *testing.T) {
	t.Parallel()

	if idn.FinishRegisterRequested(nil) {
		t.Fatal("nil payload")
	}
	if idn.FinishRegisterRequested(map[string]any{}) {
		t.Fatal("empty payload")
	}
	if !idn.FinishRegisterRequested(map[string]any{
		idn.ContinuePayloadFinishRegister: true,
	}) {
		t.Fatal("expected finish register")
	}
}

func TestRegisterPendingClaimsFromProto_roundTrip(t *testing.T) {
	t.Parallel()

	claims := &claimspb.IdentityInformation{}
	claims.SetEmail("A@B.com")
	claims.SetEmailVerified(true)
	claims.SetFederatedProvider("google")
	claims.SetFederatedSubject("sub")

	stored := session.RegisterPendingClaimsFromProto(claims)
	if stored.Email != "a@b.com" {
		t.Fatalf("email: %q", stored.Email)
	}

	back := stored.ToProto()
	if back.GetEmail() != "a@b.com" || back.GetFederatedProvider() != "google" {
		t.Fatalf("proto: %+v", back)
	}
}

func TestSessionStore_WithRegisterPending_setsStep(t *testing.T) {
	t.Parallel()

	store := session.EmailOTPStore(session.StepStart, &session.EmailOTPFlow{Email: "x@y.z"})
	claims := session.RegisterPendingClaims{Email: "x@y.z", EmailVerified: true}
	updated := store.WithRegisterPending(claims)

	if updated.Step != session.StepRegister {
		t.Fatalf("step: %s", updated.Step)
	}
	pending, ok := updated.PendingRegisterState()
	if !ok || !pending.Claims.EmailVerified {
		t.Fatalf("pending: ok=%v %+v", ok, pending)
	}

	finished := updated.WithProvisionedUserID("550e8400-e29b-41d4-a716-446655440000")
	if finished.Step != session.StepFinish {
		t.Fatalf("step: %s", finished.Step)
	}
}

func TestFinishRegisterAfterLink_deletesTransition(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := authnkv.NewKVAuthTransitionStore(mocked.NewMockKVStore())
	uid := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")

	sess, err := store.Create(ctx, "email", session.EmailOTPStore(session.StepFinish, &session.EmailOTPFlow{
		Email: "a@b.com",
	}))
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	step, err := finishRegisterAfterLink(ctx, store, sess.Id, uid, uid)
	if err != nil {
		t.Fatalf("finish: %v", err)
	}
	if step.Type != idn.StepAuthenticated || step.Authenticated.UserID != uid.String() {
		t.Fatalf("step: %+v", step)
	}

	if _, err := store.Get(ctx, sess.Id); err != session.ErrSessionNotFound {
		t.Fatalf("expected deleted transition, got %v", err)
	}
}

func TestEnsureFederatedLink_createsRow(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := openRegisterFinishTestDB(t)
	uid := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
	seedRegisterFinishUserRef(t, db, uid, "oidc@example.com")

	claims := session.RegisterPendingClaims{
		Email:             "oidc@example.com",
		EmailVerified:     true,
		FederatedProvider: "google",
		FederatedSubject:  "sub-1",
		Name:              "Ada",
	}

	linked, err := ensureFederatedLink(ctx, db, "google", "sub-1", uid, claims)
	if err != nil {
		t.Fatalf("link: %v", err)
	}
	if linked != uid {
		t.Fatalf("linked: %v", linked)
	}

	n, err := db.UserFederatedIdentity.Query().Count(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("federated rows: %d", n)
	}
}

func TestEnsureFederatedLink_idempotentWhenExists(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := openRegisterFinishTestDB(t)
	uid := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
	seedRegisterFinishUserRef(t, db, uid, "oidc@example.com")

	err := db.UserFederatedIdentity.Create().
		SetUserID(uid).
		SetProvider("google").
		SetSubject("sub-1").
		SetEmail("oidc@example.com").
		SetEmailVerified(true).
		Exec(ctx)
	if err != nil {
		t.Fatalf("seed federated: %v", err)
	}

	claims := session.RegisterPendingClaims{
		Email:             "oidc@example.com",
		FederatedProvider: "google",
		FederatedSubject:  "sub-1",
	}

	linked, err := ensureFederatedLink(ctx, db, "google", "sub-1", uid, claims)
	if err != nil {
		t.Fatalf("link: %v", err)
	}
	if linked != uid {
		t.Fatalf("linked: %v", linked)
	}
}

func TestEnsureFederatedLink_rejectsUserMismatch(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := openRegisterFinishTestDB(t)
	existing := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
	other := uuid.MustParse("6ba7b810-9dad-11d1-80b4-00c04fd430c8")
	seedRegisterFinishUserRef(t, db, existing, "a@b.com")
	seedRegisterFinishUserRef(t, db, other, "c@d.com")

	err := db.UserFederatedIdentity.Create().
		SetUserID(existing).
		SetProvider("google").
		SetSubject("sub-1").
		SetEmail("a@b.com").
		Exec(ctx)
	if err != nil {
		t.Fatalf("seed federated: %v", err)
	}

	_, err = ensureFederatedLink(ctx, db, "google", "sub-1", other, session.RegisterPendingClaims{
		Email: "c@d.com",
	})
	if !errors.Is(err, idn.ErrInvalidSessionState) {
		t.Fatalf("expected invalid session state, got %v", err)
	}
}
