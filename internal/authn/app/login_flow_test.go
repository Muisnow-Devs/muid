package app

import (
	"context"
	"testing"

	"github.com/google/uuid"
	pb "sanzi.io/muid/api/proto/authn/v1"
	sessionpb "sanzi.io/muid/api/proto/authn/v1/session"
	claimspb "sanzi.io/muid/api/proto/shared/v1/claims"
	"sanzi.io/muid/infra/mocked"
	authnkv "sanzi.io/muid/internal/authn/infra/kv"
	"sanzi.io/muid/internal/authn/infra/account"
	idpkg "sanzi.io/muid/internal/identity"
	"sanzi.io/muid/internal/session"
)

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

func (stubSessionIssuer) ResolveSessionToken(context.Context, string) (account.ResolvedSession, error) {
	panic("not used")
}

func (stubSessionIssuer) RevokeSessionToken(context.Context, string) error {
	panic("not used")
}

func (stubSessionIssuer) AuthenticatedResultFromResolved(string, account.ResolvedSession) *sessionpb.AuthenticatedResult {
	panic("not used")
}

func TestFinishAuthStep_RegisterRequired_ProvisionThenFinishContinue(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	provisioned := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")

	transitionStore := authnkv.NewKVAuthTransitionStore(mocked.NewMockKVStore())
	prov := &stubRegisterProvider{name: "email", finishUserID: provisioned.String()}
	idm := idpkg.NewIdentityManager(transitionStore, prov)

	sess, err := transitionStore.Create(ctx, "email", session.EmailOTPStore(session.StepRegister, &session.EmailOTPFlow{
		Email: "new@example.com",
	}))
	if err != nil {
		t.Fatalf("create transition: %v", err)
	}

	claims := &claimspb.IdentityInformation{}
	claims.SetEmail("new@example.com")
	claims.SetEmailVerified(true)

	h := &GRPCHandler{
		idm:             idm,
		transitionStore: transitionStore,
		accounts: &account.Accounts{
			Provision: &stubProvisioner{uid: provisioned},
			Session:   &stubSessionIssuer{},
		},
	}

	req := &pb.ContinueAuthSessionRequest{}
	req.SetTransitionId(sess.Id)

	resp, err := h.finishAuthStep(ctx, req, sess, idpkg.StepResult{
		Type: idpkg.StepRegisterRequired,
		RegisterRequired: &idpkg.RegisterRequired{
			Identity: claims,
		},
	})
	if err != nil {
		t.Fatalf("finishAuthStep: %v", err)
	}
	if prov.finishCalls != 1 {
		t.Fatalf("finish continue calls: %d", prov.finishCalls)
	}
	if resp == nil || !resp.HasAuthSuccess() {
		t.Fatal("expected auth success response")
	}

	updated, err := transitionStore.Get(ctx, sess.Id)
	if err != nil {
		t.Fatalf("get transition after provision: %v", err)
	}
	pending, ok := updated.Store.PendingRegisterState()
	if !ok || pending.ProvisionedUserID != provisioned.String() || updated.Store.Step != session.StepFinish {
		t.Fatalf("after provision: step=%s ok=%v pending=%+v", updated.Store.Step, ok, pending)
	}
}
