package flow

import (
	"context"
	"errors"
	"testing"

	pb "sanzi.io/muid/api/proto/authn/v1"
	"sanzi.io/muid/api/proto/authn/v1/basic"
	proofpb "sanzi.io/muid/api/proto/authn/v1/proof"
	"sanzi.io/muid/infra/mocked"
	authnkv "sanzi.io/muid/internal/authn/kv"
	"sanzi.io/muid/internal/identity"
	"sanzi.io/muid/internal/session"
)

type otpInputStubProvider struct{}

func (otpInputStubProvider) Name() string { return "email" }

func (otpInputStubProvider) Start(
	context.Context,
	identity.StartInput,
) (identity.StepResult, error) {
	return identity.StepResult{}, errors.New("unused")
}

func (otpInputStubProvider) Continue(
	_ context.Context,
	in identity.ContinueInput,
) (identity.StepResult, error) {
	if in.ContinueState == identity.ContinueStateResend {
		return identity.StepResult{TransitionId: in.TransitionId, Type: identity.StepInput}, nil
	}
	return identity.StepResult{}, errors.New("unsupported")
}

func TestContinueAuthSession_StepInputReturnsChallengeRequired(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	kv := mocked.NewMockKVStore()
	trans := authnkv.NewKVAuthTransitionStore(kv)

	sess, err := trans.Create(
		ctx,
		"email",
		session.EmailOTPStore(session.StepStart, &session.EmailOTPFlow{
			Email: "user@example.com",
		}),
	)
	if err != nil {
		t.Fatalf("create transition: %v", err)
	}

	idm := identity.NewIdentityManager(trans, otpInputStubProvider{})
	svc := NewService(Dependencies{
		IdentityManager:        idm,
		TransitionStore:        trans,
		OTPSendCooldownSeconds: 60,
	})

	ep := &proofpb.EmailProof{}
	ep.SetResend(&proofpb.EmailResendOtp{})
	proof := &proofpb.AuthProof{}
	proof.SetEmailProof(ep)

	req := &pb.ContinueAuthSessionRequest{}
	req.SetTransitionId(sess.Id)
	req.SetProof(proof)

	resp, err := svc.ContinueAuthSession(ctx, req, sess.Id, "")
	if err != nil {
		t.Fatalf("ContinueAuthSession: %v", err)
	}
	if resp.GetTransitionId() != sess.Id {
		t.Fatalf("transition id: got %q want %q", resp.GetTransitionId(), sess.Id)
	}
	if resp.GetStatus() != basic.AuthStatus_AUTH_STATUS_CHALLENGE_REQUIRED {
		t.Fatalf("status: got %v", resp.GetStatus())
	}
	if !resp.HasChallengeRequired() || !resp.GetChallengeRequired().HasChallenge() {
		t.Fatal("expected challenge_required with challenge")
	}
}
