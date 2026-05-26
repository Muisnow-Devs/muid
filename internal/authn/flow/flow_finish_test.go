package flow

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	pb "sanzi.io/muid/api/proto/authn/v1"
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
	if idpkg.FinishRegisterRequested(input.Payload) {
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
	if idpkg.FinishRegisterRequested(input.Payload) {
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

	updated, err := transitionStore.Get(ctx, staleSess.Id)
	if err != nil {
		t.Fatalf("get transition after provision: %v", err)
	}
	pending, ok := updated.Store.PendingRegisterState()
	if !ok || pending.ProvisionedUserID != provisioned.String() ||
		pending.Claims.Email != "new@example.com" ||
		updated.Store.Step != session.StepFinish {
		t.Fatalf("after provision: step=%s ok=%v pending=%+v", updated.Store.Step, ok, pending)
	}
}
