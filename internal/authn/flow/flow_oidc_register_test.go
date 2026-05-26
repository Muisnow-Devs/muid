package flow

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	claimspb "sanzi.io/muid/api/proto/shared/v1/claims"
	sessionpb "sanzi.io/muid/api/proto/authn/v1/session"
	"sanzi.io/muid/infra/mocked"
	"sanzi.io/muid/internal/authn/account"
	authnkv "sanzi.io/muid/internal/authn/kv"
	"sanzi.io/muid/internal/identity"
	"sanzi.io/muid/internal/session"
	"sanzi.io/muid/pkg/shared/pubsub"
)

type stubEmailLookup struct {
	byEmail map[string]uuid.UUID
}

func (s *stubEmailLookup) LookupUserByEmail(
	_ context.Context,
	email string,
) (uuid.UUID, bool, error) {
	uid, ok := s.byEmail[email]
	return uid, ok, nil
}

func (stubEmailLookup) UserEmail(context.Context, uuid.UUID) (string, error) {
	panic("not used")
}

func (stubEmailLookup) EmailUsedByOther(context.Context, string, uuid.UUID) (bool, error) {
	panic("not used")
}

func (stubEmailLookup) ChangeUserEmail(
	context.Context,
	pubsub.PubSub,
	uuid.UUID,
	string,
	account.MailDeliveryPrefs,
) (string, error) {
	panic("not used")
}

type stubLinkSessionResolver struct {
	userID      uuid.UUID
	issuedWire  string
	revokedWire string
}

func (s *stubLinkSessionResolver) IssueAuthenticatedSession(
	_ context.Context,
	userID uuid.UUID,
) (*sessionpb.AuthenticatedResult, error) {
	wire := s.issuedWire
	if wire == "" {
		wire = "issued.new.session.token"
	}
	stok := &sessionpb.SessionToken{}
	stok.SetValue(wire)

	sctx := &sessionpb.SessionContext{}
	sctx.SetSessionToken(stok)

	out := &sessionpb.AuthenticatedResult{}
	out.SetUserId(userID.String())
	out.SetSessionContext(sctx)
	return out, nil
}

func (s *stubLinkSessionResolver) ResolveSessionToken(
	context.Context,
	string,
) (account.ResolvedSession, error) {
	return account.ResolvedSession{UserID: s.userID}, nil
}

func (s *stubLinkSessionResolver) RevokeSessionToken(_ context.Context, wire string) error {
	s.revokedWire = wire
	return nil
}

func (stubLinkSessionResolver) SessionCreatedAt(context.Context, uuid.UUID) (time.Time, error) {
	panic("not used")
}

func (stubLinkSessionResolver) AuthenticatedResultFromResolved(
	string,
	account.ResolvedSession,
) *sessionpb.AuthenticatedResult {
	panic("not used")
}

func (stubLinkSessionResolver) AuthenticatedPrincipalFromResolved(
	account.ResolvedSession,
) *sessionpb.AuthenticatedPrincipal {
	panic("not used")
}

func oidcRegisterRequired(provider, subject, email string) *identity.RegisterRequired {
	id := &claimspb.IdentityInformation{}
	id.SetEmail(email)
	id.SetEmailVerified(true)
	id.SetFederatedProvider(provider)
	id.SetFederatedSubject(subject)
	return &identity.RegisterRequired{Identity: id}
}

func TestResolveOIDCLoginRegister_returnsExistingUserID(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	existing := uuid.MustParse("550e8400-e29b-41d4-a716-446655440001")
	svc := &Service{
		email: &stubEmailLookup{byEmail: map[string]uuid.UUID{
			"exists@example.com": existing,
		}},
	}

	uid, existingUser, err := svc.resolveOIDCLoginRegister(
		ctx,
		oidcRegisterRequired("google", "sub", "exists@example.com"),
	)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if uid != existing || !existingUser {
		t.Fatalf("got uid=%v existing=%v", uid, existingUser)
	}
}

func TestResolveOIDCLoginRegister_provisionsWhenEmailUnknown(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	provisioned := uuid.MustParse("550e8400-e29b-41d4-a716-446655440099")
	svc := &Service{
		email:     &stubEmailLookup{byEmail: map[string]uuid.UUID{}},
		provision: &stubProvisioner{uid: provisioned},
	}

	uid, existingUser, err := svc.resolveOIDCLoginRegister(
		ctx,
		oidcRegisterRequired("google", "sub-new", "new@example.com"),
	)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if uid != provisioned || existingUser {
		t.Fatalf("got uid=%v existing=%v", uid, existingUser)
	}
}

func TestResolveOIDCLinkRegister_withoutWireTokenRejected(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	linkUser := uuid.MustParse("550e8400-e29b-41d4-a716-446655440002")

	svc := &Service{
		sessions: &stubLinkSessionResolver{userID: linkUser},
	}

	store := session.OIDCStore(session.StepRegister, &session.OIDCFlow{OAuthState: "st"}).
		WithAuthContext(string(identity.IntentLinkAccount), linkUser.String())

	_, err := svc.resolveOIDCLinkRegister(ctx, store, "")
	if !errors.Is(err, identity.ErrLinkUnauthorized) {
		t.Fatalf("got %v want ErrLinkUnauthorized", err)
	}
}

func TestResolveOIDCLinkRegister_wrongSessionUserRejected(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	linkUser := uuid.MustParse("550e8400-e29b-41d4-a716-446655440002")
	other := uuid.MustParse("6ba7b810-9dad-11d1-80b4-00c04fd430c8")

	svc := &Service{
		sessions: &stubLinkSessionResolver{userID: other},
	}

	store := session.OIDCStore(session.StepRegister, &session.OIDCFlow{OAuthState: "st"}).
		WithAuthContext(string(identity.IntentLinkAccount), linkUser.String())

	_, err := svc.resolveOIDCLinkRegister(ctx, store, "wire-token")
	if !errors.Is(err, identity.ErrLinkUnauthorized) {
		t.Fatalf("got %v want ErrLinkUnauthorized", err)
	}
}

func TestResolveOIDCLinkRegister_returnsLinkUserWithoutEmailLookup(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	linkUser := uuid.MustParse("550e8400-e29b-41d4-a716-446655440002")
	other := uuid.MustParse("6ba7b810-9dad-11d1-80b4-00c04fd430c8")

	svc := &Service{
		email: &stubEmailLookup{byEmail: map[string]uuid.UUID{
			"taken@example.com": other,
		}},
		sessions: &stubLinkSessionResolver{userID: linkUser},
	}

	store := session.OIDCStore(session.StepRegister, &session.OIDCFlow{OAuthState: "st"}).
		WithAuthContext(string(identity.IntentLinkAccount), linkUser.String())

	uid, err := svc.resolveOIDCLinkRegister(ctx, store, "wire-token")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if uid != linkUser {
		t.Fatalf("uid: got %v want %v", uid, linkUser)
	}
}

func TestMapContinueError_cleansTransitionOnAuthFailure(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := authnkv.NewKVAuthTransitionStore(mocked.NewMockKVStore())
	sess, err := store.Create(
		ctx,
		"google",
		session.OIDCStore(session.StepRegister, &session.OIDCFlow{OAuthState: "st"}),
	)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	svc := &Service{transitionStore: store}
	resp, err := svc.mapContinueError(ctx, sess.Id, identity.ErrOIDCManualAccountLinkingRequired)
	if err != nil {
		t.Fatalf("mapContinueError: %v", err)
	}
	if resp == nil || !resp.HasAuthFailure() {
		t.Fatal("expected auth failure")
	}

	_, err = store.Get(ctx, sess.Id)
	if !errors.Is(err, session.ErrSessionNotFound) {
		t.Fatalf("transition should be deleted, got %v", err)
	}
}
