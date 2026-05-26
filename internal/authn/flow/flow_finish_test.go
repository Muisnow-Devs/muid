package flow

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	pb "sanzi.io/muid/api/proto/authn/v1"
	"sanzi.io/muid/api/proto/authn/v1/basic"
	sessionpb "sanzi.io/muid/api/proto/authn/v1/session"
	claimspb "sanzi.io/muid/api/proto/shared/v1/claims"
	"sanzi.io/muid/infra/mocked"
	"sanzi.io/muid/internal/authn/account"
	authnkv "sanzi.io/muid/internal/authn/kv"
	idpkg "sanzi.io/muid/internal/identity"
	"sanzi.io/muid/internal/session"
)

func TestLoginAlertDetails_fromCompletion(t *testing.T) {
	t.Parallel()

	got := loginAlertDetails(&idpkg.LoginCompletionContext{
		Device:    "Chrome",
		Location:  "TW",
		IPAddress: "203.0.113.1",
		UserAgent: "Mozilla/5.0",
	})
	if got.Device != "Chrome" || got.IPAddress != "203.0.113.1" {
		t.Fatalf("details: %+v", got)
	}
}

func TestLoginCompletionForAlert_prefersTransitionStore(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	transitionStore := authnkv.NewKVAuthTransitionStore(mocked.NewMockKVStore())

	store := session.EmailOTPStore(
		session.StepContinue,
		&session.EmailOTPFlow{Email: "user@example.com"},
	)
	store.Device = "Chrome on macOS"
	store.Location = "Taipei, TW"
	store.IPAddress = "203.0.113.1"
	store.Locale = "zh-TW"
	store.Timezone = "Asia/Taipei"

	sess, err := transitionStore.Create(ctx, "email", store)
	if err != nil {
		t.Fatalf("create transition: %v", err)
	}

	svc := NewService(Dependencies{TransitionStore: transitionStore})

	got := svc.loginCompletionForAlert(ctx, sess.Id, &idpkg.LoginCompletionContext{
		Device: "stale device",
	})
	if got == nil {
		t.Fatal("expected completion")
	}
	if got.Device != "Chrome on macOS" || got.Location != "Taipei, TW" {
		t.Fatalf("completion: %+v", got)
	}
	if got.IPAddress != "203.0.113.1" || got.Locale != "zh-TW" {
		t.Fatalf("completion: %+v", got)
	}
}

func TestAuthenticatedLoginResponse_loginAlertFromTransition(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	uid := uuid.MustParse("550e8400-e29b-41d4-a716-446655440010")

	transitionStore := authnkv.NewKVAuthTransitionStore(mocked.NewMockKVStore())
	store := session.EmailOTPStore(
		session.StepContinue,
		&session.EmailOTPFlow{Email: "user@example.com"},
	)
	store.Device = "Safari on iPhone"
	store.Location = "Taipei, TW"
	store.IPAddress = "198.51.100.2"
	store.Locale = "en"
	store.Timezone = "UTC"

	sess, err := transitionStore.Create(ctx, "email", store)
	if err != nil {
		t.Fatalf("create transition: %v", err)
	}

	loginNotifier := &stubNotifier{}
	svc := NewService(Dependencies{
		TransitionStore: transitionStore,
		Sessions:        &stubSessionIssuer{},
		Notifier:        loginNotifier,
	})

	_, err = svc.authenticatedLoginResponse(ctx, sess.Id, &idpkg.AuthenticatedIdentity{
		UserID: uid.String(),
	}, nil)
	if err != nil {
		t.Fatalf("authenticatedLoginResponse: %v", err)
	}
	if loginNotifier.loginCalls != 1 {
		t.Fatalf("notify calls: %d", loginNotifier.loginCalls)
	}
	if loginNotifier.loginUserID != uid {
		t.Fatalf("notify user: %s", loginNotifier.loginUserID)
	}
	if loginNotifier.loginDetails.Device != "Safari on iPhone" ||
		loginNotifier.loginDetails.IPAddress != "198.51.100.2" {
		t.Fatalf("notify details: %+v", loginNotifier.loginDetails)
	}
	if loginNotifier.loginPrefs.Locale != "en" || loginNotifier.loginPrefs.Timezone != "UTC" {
		t.Fatalf("notify prefs: %+v", loginNotifier.loginPrefs)
	}

	_, err = transitionStore.Get(ctx, sess.Id)
	if err != session.ErrSessionNotFound {
		t.Fatalf("expected transition deleted, got %v", err)
	}
}

type stubRegisterProvider struct {
	name         string
	finishUserID string
	finishCalls  int
}

func (s *stubRegisterProvider) Name() string { return s.name }

func (s *stubRegisterProvider) Start(context.Context, idpkg.StartInput) (idpkg.StepResult, error) {
	return idpkg.StepResult{}, nil
}

func (s *stubRegisterProvider) Continue(
	_ context.Context,
	input idpkg.ContinueInput,
) (idpkg.StepResult, error) {
	if input.ContinueState == idpkg.ContinueStateFinishRegister {
		s.finishCalls++
		return idpkg.StepResult{
			Type: idpkg.StepAuthenticated,
			Authenticated: &idpkg.AuthenticatedIdentity{
				UserID: s.finishUserID,
			},
		}, nil
	}
	return idpkg.StepResult{}, nil
}

type stubProvisioner struct {
	uid uuid.UUID
}

func (s *stubProvisioner) ProvisionUser(
	context.Context,
	*idpkg.RegisterRequired,
) (uuid.UUID, error) {
	return s.uid, nil
}

type stubSessionIssuer struct {
	issued *sessionpb.AuthenticatedResult
}

func (s *stubSessionIssuer) IssueAuthenticatedSession(
	context.Context,
	uuid.UUID,
) (*sessionpb.AuthenticatedResult, error) {
	if s.issued != nil {
		return s.issued, nil
	}
	out := &sessionpb.AuthenticatedResult{}
	return out, nil
}

func (stubSessionIssuer) ResolveSessionToken(
	context.Context,
	string,
) (account.ResolvedSession, error) {
	panic("not used")
}

func (stubSessionIssuer) RevokeSessionToken(context.Context, string) error {
	panic("not used")
}

func (stubSessionIssuer) SessionCreatedAt(context.Context, uuid.UUID) (time.Time, error) {
	panic("not used")
}

func (stubSessionIssuer) AuthenticatedResultFromResolved(
	string,
	account.ResolvedSession,
) *sessionpb.AuthenticatedResult {
	panic("not used")
}

func (stubSessionIssuer) AuthenticatedPrincipalFromResolved(
	account.ResolvedSession,
) *sessionpb.AuthenticatedPrincipal {
	panic("not used")
}

// pendingClaimsRegisterProvider simulates a login Continue that persists register claims
// before the flow layer provisions the user.
type pendingClaimsRegisterProvider struct {
	name            string
	finishUserID    string
	transitionStore session.AuthTransitionStore
}

func (s *pendingClaimsRegisterProvider) Name() string { return s.name }

func (s *pendingClaimsRegisterProvider) Start(
	context.Context,
	idpkg.StartInput,
) (idpkg.StepResult, error) {
	return idpkg.StepResult{}, nil
}

func (s *pendingClaimsRegisterProvider) Continue(
	ctx context.Context,
	input idpkg.ContinueInput,
) (idpkg.StepResult, error) {
	if input.ContinueState == idpkg.ContinueStateFinishRegister {
		sess, err := s.transitionStore.Get(ctx, input.TransitionId)
		if err != nil {
			return idpkg.StepResult{}, err
		}
		pending, ok := sess.Store.PendingRegisterState()
		if !ok || pending.Claims.Email == "" {
			return idpkg.StepResult{}, idpkg.ErrInvalidSessionState
		}
		return idpkg.StepResult{
			Type: idpkg.StepAuthenticated,
			Authenticated: &idpkg.AuthenticatedIdentity{
				UserID: s.finishUserID,
			},
		}, nil
	}
	return idpkg.StepResult{}, nil
}

func TestFinishAuthStep_RegisterRequired_preservesPendingClaims(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	provisioned := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")

	transitionStore := authnkv.NewKVAuthTransitionStore(mocked.NewMockKVStore())
	prov := &pendingClaimsRegisterProvider{
		name:            "email",
		finishUserID:    provisioned.String(),
		transitionStore: transitionStore,
	}
	idm := idpkg.NewIdentityManager(transitionStore, prov)

	staleSess, err := transitionStore.Create(
		ctx,
		"email",
		session.EmailOTPStore(session.StepStart, &session.EmailOTPFlow{
			Email: "new@example.com",
		}),
	)
	if err != nil {
		t.Fatalf("create transition: %v", err)
	}

	claims := session.RegisterPendingClaims{
		Email:         "new@example.com",
		EmailVerified: true,
	}
	err = transitionStore.Update(
		ctx,
		staleSess.Id,
		staleSess.Store.WithRegisterPending(claims),
	)
	if err != nil {
		t.Fatalf("persist register pending: %v", err)
	}

	protoClaims := &claimspb.IdentityInformation{}
	protoClaims.SetEmail("new@example.com")
	protoClaims.SetEmailVerified(true)

	svc := NewService(Dependencies{
		IdentityManager: idm,
		TransitionStore: transitionStore,
		Provision:       &stubProvisioner{uid: provisioned},
		Sessions:        &stubSessionIssuer{},
	})

	req := &pb.ContinueAuthSessionRequest{}
	req.SetTransitionId(staleSess.Id)

	resp, err := svc.finishAuthStep(ctx, req, staleSess, idpkg.StepResult{
		Type: idpkg.StepRegisterRequired,
		RegisterRequired: &idpkg.RegisterRequired{
			Identity: protoClaims,
		},
	}, staleSess.Id, "")
	if err != nil {
		t.Fatalf("finishAuthStep: %v", err)
	}
	if resp == nil || !resp.HasAuthSuccess() {
		t.Fatal("expected auth success response")
	}
}

func TestFinishAuthStep_RegisterRequired_ProvisionThenFinishContinue(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	provisioned := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")

	transitionStore := authnkv.NewKVAuthTransitionStore(mocked.NewMockKVStore())
	prov := &stubRegisterProvider{name: "email", finishUserID: provisioned.String()}
	idm := idpkg.NewIdentityManager(transitionStore, prov)

	staleSess, err := transitionStore.Create(
		ctx,
		"email",
		session.EmailOTPStore(session.StepStart, &session.EmailOTPFlow{
			Email: "new@example.com",
		}),
	)
	if err != nil {
		t.Fatalf("create transition: %v", err)
	}

	err = transitionStore.Update(
		ctx,
		staleSess.Id,
		staleSess.Store.WithRegisterPending(session.RegisterPendingClaims{
			Email:         "new@example.com",
			EmailVerified: true,
		}),
	)
	if err != nil {
		t.Fatalf("persist register pending: %v", err)
	}

	claims := &claimspb.IdentityInformation{}
	claims.SetEmail("new@example.com")
	claims.SetEmailVerified(true)

	svc := NewService(Dependencies{
		IdentityManager: idm,
		TransitionStore: transitionStore,
		Provision:       &stubProvisioner{uid: provisioned},
		Sessions:        &stubSessionIssuer{},
	})

	req := &pb.ContinueAuthSessionRequest{}
	req.SetTransitionId(staleSess.Id)

	resp, err := svc.finishAuthStep(ctx, req, staleSess, idpkg.StepResult{
		Type: idpkg.StepRegisterRequired,
		RegisterRequired: &idpkg.RegisterRequired{
			Identity: claims,
		},
	}, staleSess.Id, "")
	if err != nil {
		t.Fatalf("finishAuthStep: %v", err)
	}
	if prov.finishCalls != 1 {
		t.Fatalf("finish continue calls: %d", prov.finishCalls)
	}
	if resp == nil || !resp.HasAuthSuccess() {
		t.Fatal("expected auth success response")
	}

	// Transition is deleted by flow after StepAuthenticated — verify it was cleaned up.
	_, err = transitionStore.Get(ctx, staleSess.Id)
	if err != session.ErrSessionNotFound {
		t.Fatalf("expected transition deleted after authenticated, got %v", err)
	}
}

type stubOIDCLinkFinishProvider struct {
	transitionStore session.AuthTransitionStore
}

func (s *stubOIDCLinkFinishProvider) Name() string { return "google" }

func (s *stubOIDCLinkFinishProvider) Start(
	context.Context,
	idpkg.StartInput,
) (idpkg.StepResult, error) {
	return idpkg.StepResult{}, nil
}

func (s *stubOIDCLinkFinishProvider) Continue(
	ctx context.Context,
	input idpkg.ContinueInput,
) (idpkg.StepResult, error) {
	if input.ContinueState != idpkg.ContinueStateFinishRegister {
		return idpkg.StepResult{}, nil
	}
	if _, err := idpkg.ProvisionedUserID(input); err != nil {
		return idpkg.StepResult{}, err
	}
	sess, err := s.transitionStore.Get(ctx, input.TransitionId)
	if err != nil {
		return idpkg.StepResult{}, err
	}
	pending, ok := sess.Store.PendingRegisterState()
	if !ok || pending.Claims.FederatedProvider == "" {
		return idpkg.StepResult{}, idpkg.ErrInvalidSessionState
	}
	return idpkg.StepResult{Type: idpkg.StepLinked}, nil
}

func TestFinishAuthStep_OIDCLinkRegister_withoutContinueSessionTokenRejected(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	linkUser := uuid.MustParse("550e8400-e29b-41d4-a716-446655440003")

	transitionStore := authnkv.NewKVAuthTransitionStore(mocked.NewMockKVStore())
	prov := &stubOIDCLinkFinishProvider{transitionStore: transitionStore}
	idm := idpkg.NewIdentityManager(transitionStore, prov)

	store := session.OIDCStore(session.StepRegister, &session.OIDCFlow{
		OAuthState: "oauth-state",
	}).WithAuthContext(string(idpkg.IntentLinkAccount), linkUser.String())

	store = store.WithRegisterPending(session.RegisterPendingClaims{
		Email:             "link@example.com",
		EmailVerified:     true,
		FederatedProvider: "google",
		FederatedSubject:  "sub-link",
	})

	sess, err := transitionStore.Create(ctx, "google", store)
	if err != nil {
		t.Fatalf("create transition: %v", err)
	}

	protoClaims := &claimspb.IdentityInformation{}
	protoClaims.SetEmail("link@example.com")
	protoClaims.SetEmailVerified(true)
	protoClaims.SetFederatedProvider("google")
	protoClaims.SetFederatedSubject("sub-link")

	svc := NewService(Dependencies{
		IdentityManager: idm,
		TransitionStore: transitionStore,
		Sessions:        &stubLinkSessionResolver{userID: linkUser},
	})

	req := &pb.ContinueAuthSessionRequest{}
	req.SetTransitionId(sess.Id)

	resp, err := svc.finishAuthStep(ctx, req, sess, idpkg.StepResult{
		Type: idpkg.StepRegisterRequired,
		RegisterRequired: &idpkg.RegisterRequired{
			Identity: protoClaims,
		},
	}, sess.Id, "")
	if err != nil {
		t.Fatalf("finishAuthStep: %v", err)
	}
	if resp == nil || !resp.HasAuthFailure() {
		t.Fatalf("expected link unauthorized failure, got %+v", resp)
	}
	if resp.GetAuthFailure().GetErrorCode() != ErrCodeLinkUnauthorized {
		t.Fatalf(
			"error_code: got %q want %q",
			resp.GetAuthFailure().GetErrorCode(),
			ErrCodeLinkUnauthorized,
		)
	}
}

func TestFinishAuthStep_OIDCLinkRegister_withMatchingSessionToken(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	linkUser := uuid.MustParse("550e8400-e29b-41d4-a716-446655440003")
	const continueWire = "link.selector.validator"

	transitionStore := authnkv.NewKVAuthTransitionStore(mocked.NewMockKVStore())
	prov := &stubOIDCLinkFinishProvider{transitionStore: transitionStore}
	idm := idpkg.NewIdentityManager(transitionStore, prov)

	store := session.OIDCStore(session.StepRegister, &session.OIDCFlow{
		OAuthState: "oauth-state",
	}).WithAuthContext(string(idpkg.IntentLinkAccount), linkUser.String())
	store.Locale = "zh-TW"
	store.Timezone = "Asia/Taipei"

	store = store.WithRegisterPending(session.RegisterPendingClaims{
		Email:             "link@example.com",
		EmailVerified:     true,
		FederatedProvider: "google",
		FederatedSubject:  "sub-link",
	})

	sess, err := transitionStore.Create(ctx, "google", store)
	if err != nil {
		t.Fatalf("create transition: %v", err)
	}

	protoClaims := &claimspb.IdentityInformation{}
	protoClaims.SetEmail("link@example.com")
	protoClaims.SetEmailVerified(true)
	protoClaims.SetFederatedProvider("google")
	protoClaims.SetFederatedSubject("sub-link")

	sessions := &stubLinkSessionResolver{userID: linkUser}
	linkNotifier := &stubNotifier{}
	svc := NewService(Dependencies{
		IdentityManager: idm,
		TransitionStore: transitionStore,
		Sessions:        sessions,
		Notifier:        linkNotifier,
	})

	req := &pb.ContinueAuthSessionRequest{}
	req.SetTransitionId(sess.Id)

	resp, err := svc.finishAuthStep(ctx, req, sess, idpkg.StepResult{
		Type: idpkg.StepRegisterRequired,
		RegisterRequired: &idpkg.RegisterRequired{
			Identity: protoClaims,
		},
	}, sess.Id, continueWire)
	if err != nil {
		t.Fatalf("finishAuthStep: %v", err)
	}
	if resp == nil || resp.GetStatus() != basic.AuthStatus_AUTH_STATUS_AUTHENTICATED {
		t.Fatalf("response: %+v", resp)
	}
	if !resp.HasAuthSuccess() {
		t.Fatal("expected auth success with session token after link")
	}
	if sessions.revokedWire != continueWire {
		t.Fatalf("revoked wire: got %q want %q", sessions.revokedWire, continueWire)
	}
	gotWire := resp.GetAuthSuccess().GetResult().GetSessionContext().GetSessionToken().GetValue()
	if gotWire == continueWire {
		t.Fatalf("session_token must be newly issued, got request wire %q", gotWire)
	}
	if gotWire != "issued.new.session.token" {
		t.Fatalf("session_token: got %q want newly issued stub token", gotWire)
	}
	if linkNotifier.accountLinkedCalls != 1 {
		t.Fatalf("account link notify calls: %d", linkNotifier.accountLinkedCalls)
	}
	if linkNotifier.accountLinkedUser != linkUser {
		t.Fatalf("notify user_id: %s", linkNotifier.accountLinkedUser)
	}
	if linkNotifier.accountLinkedProv != "google" {
		t.Fatalf("notify provider: %q", linkNotifier.accountLinkedProv)
	}
	if linkNotifier.accountLinkedPrefs.Locale != "zh-TW" ||
		linkNotifier.accountLinkedPrefs.Timezone != "Asia/Taipei" {
		t.Fatalf("notify mail prefs: %+v", linkNotifier.accountLinkedPrefs)
	}

	_, err = transitionStore.Get(ctx, sess.Id)
	if err != session.ErrSessionNotFound {
		t.Fatalf("expected transition deleted after link, got %v", err)
	}
}

func TestLinkCompletedResponse_linkIntent_withoutWireRejected(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	linkUser := uuid.MustParse("550e8400-e29b-41d4-a716-446655440004")

	transitionStore := authnkv.NewKVAuthTransitionStore(mocked.NewMockKVStore())
	store := session.OIDCStore(session.StepContinue, &session.OIDCFlow{
		OAuthState: "oauth-state",
	}).WithAuthContext(string(idpkg.IntentLinkAccount), linkUser.String())

	sess, err := transitionStore.Create(ctx, "google", store)
	if err != nil {
		t.Fatalf("create transition: %v", err)
	}

	svc := NewService(Dependencies{
		TransitionStore: transitionStore,
		Sessions:        &stubLinkSessionResolver{userID: linkUser},
	})

	resp, err := svc.linkCompletedResponse(ctx, sess.Id, "")
	if err != nil {
		t.Fatalf("linkCompletedResponse: %v", err)
	}
	if resp == nil || !resp.HasAuthFailure() {
		t.Fatalf("expected link unauthorized failure, got %+v", resp)
	}
	if resp.GetAuthFailure().GetErrorCode() != ErrCodeLinkUnauthorized {
		t.Fatalf(
			"error_code: got %q want %q",
			resp.GetAuthFailure().GetErrorCode(),
			ErrCodeLinkUnauthorized,
		)
	}
}

func TestLinkCompletedResponse_linkIntent_withRequestWire(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	linkUser := uuid.MustParse("550e8400-e29b-41d4-a716-446655440004")
	const continueWire = "continue.selector.validator"

	transitionStore := authnkv.NewKVAuthTransitionStore(mocked.NewMockKVStore())
	store := session.OIDCStore(session.StepContinue, &session.OIDCFlow{
		OAuthState: "oauth-state",
	}).WithAuthContext(string(idpkg.IntentLinkAccount), linkUser.String())
	store.Locale = "en"
	store.Timezone = "UTC"

	sess, err := transitionStore.Create(ctx, "google", store)
	if err != nil {
		t.Fatalf("create transition: %v", err)
	}

	sessions := &stubLinkSessionResolver{userID: linkUser}
	linkNotifier := &stubNotifier{}
	svc := NewService(Dependencies{
		TransitionStore: transitionStore,
		Sessions:        sessions,
		Notifier:        linkNotifier,
	})

	resp, err := svc.linkCompletedResponse(ctx, sess.Id, continueWire)
	if err != nil {
		t.Fatalf("linkCompletedResponse: %v", err)
	}
	if resp == nil || !resp.HasAuthSuccess() {
		t.Fatal("expected auth success")
	}
	if sessions.revokedWire != continueWire {
		t.Fatalf("revoked wire: got %q want %q", sessions.revokedWire, continueWire)
	}
	gotWire := resp.GetAuthSuccess().GetResult().GetSessionContext().GetSessionToken().GetValue()
	if gotWire == continueWire {
		t.Fatalf("session_token must be newly issued, got request wire %q", gotWire)
	}
	if gotWire != "issued.new.session.token" {
		t.Fatalf("session_token: got %q want newly issued stub token", gotWire)
	}
	if linkNotifier.accountLinkedCalls != 1 {
		t.Fatalf("account link notify calls: %d", linkNotifier.accountLinkedCalls)
	}
	if linkNotifier.accountLinkedUser != linkUser || linkNotifier.accountLinkedProv != "google" {
		t.Fatalf(
			"notify user/provider: %s / %q",
			linkNotifier.accountLinkedUser,
			linkNotifier.accountLinkedProv,
		)
	}
}
