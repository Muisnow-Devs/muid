package flow

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	pb "sanzi.io/muid/api/proto/authn/v1"
	"sanzi.io/muid/api/proto/authn/v1/basic"
	proofpb "sanzi.io/muid/api/proto/authn/v1/proof"
	"sanzi.io/muid/infra/mocked"
	authnkv "sanzi.io/muid/internal/authn/kv"
	idpkg "sanzi.io/muid/internal/identity"
	"sanzi.io/muid/internal/session"
)

type linkContinueStubProvider struct{}

func (linkContinueStubProvider) Name() string { return "google" }

func (linkContinueStubProvider) Start(
	context.Context,
	idpkg.StartInput,
) (idpkg.StepResult, error) {
	return idpkg.StepResult{}, errors.New("unused")
}

func (linkContinueStubProvider) Continue(
	_ context.Context,
	in idpkg.ContinueInput,
) (idpkg.StepResult, error) {
	if in.ContinueState == idpkg.ContinueStateChallenge {
		return idpkg.StepResult{TransitionId: in.TransitionId, Type: idpkg.StepInput}, nil
	}
	return idpkg.StepResult{}, errors.New("unsupported")
}

func TestContinueAuthSession_linkIntentWithoutSessionTokenRejected(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	linkUser := uuid.MustParse("550e8400-e29b-41d4-a716-446655440010")

	trans := authnkv.NewKVAuthTransitionStore(mocked.NewMockKVStore())
	sess, err := trans.Create(
		ctx,
		"google",
		session.OIDCStore(session.StepContinue, &session.OIDCFlow{OAuthState: "st"}).
			WithAuthContext(string(idpkg.IntentLinkAccount), linkUser.String()),
	)
	if err != nil {
		t.Fatalf("create transition: %v", err)
	}

	idm := idpkg.NewIdentityManager(trans, linkContinueStubProvider{})
	svc := NewService(Dependencies{
		IdentityManager: idm,
		TransitionStore: trans,
		Sessions:        &stubLinkSessionResolver{userID: linkUser},
	})

	op := &proofpb.OAuthProof{}
	op.SetCode("code")
	op.SetState("st")
	proof := &proofpb.AuthProof{}
	proof.SetOauthProof(op)

	req := &pb.ContinueAuthSessionRequest{}
	req.SetTransitionId(sess.Id)
	req.SetProof(proof)

	resp, err := svc.ContinueAuthSession(ctx, req, sess.Id, "")
	if err != nil {
		t.Fatalf("ContinueAuthSession: %v", err)
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

func TestContinueAuthSession_linkIntentWithWrongSessionTokenRejected(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	linkUser := uuid.MustParse("550e8400-e29b-41d4-a716-446655440012")
	other := uuid.MustParse("6ba7b810-9dad-11d1-80b4-00c04fd430c8")

	trans := authnkv.NewKVAuthTransitionStore(mocked.NewMockKVStore())
	sess, err := trans.Create(
		ctx,
		"google",
		session.OIDCStore(session.StepContinue, &session.OIDCFlow{OAuthState: "st"}).
			WithAuthContext(string(idpkg.IntentLinkAccount), linkUser.String()),
	)
	if err != nil {
		t.Fatalf("create transition: %v", err)
	}

	idm := idpkg.NewIdentityManager(trans, linkContinueStubProvider{})
	svc := NewService(Dependencies{
		IdentityManager: idm,
		TransitionStore: trans,
		Sessions:        &stubLinkSessionResolver{userID: other},
	})

	op := &proofpb.OAuthProof{}
	op.SetCode("code")
	op.SetState("st")
	proof := &proofpb.AuthProof{}
	proof.SetOauthProof(op)

	req := &pb.ContinueAuthSessionRequest{}
	req.SetTransitionId(sess.Id)
	req.SetProof(proof)

	resp, err := svc.ContinueAuthSession(ctx, req, sess.Id, "wire-token")
	if err != nil {
		t.Fatalf("ContinueAuthSession: %v", err)
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

func TestContinueAuthSession_linkIntentWithMatchingSessionTokenAllowed(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	linkUser := uuid.MustParse("550e8400-e29b-41d4-a716-446655440011")

	trans := authnkv.NewKVAuthTransitionStore(mocked.NewMockKVStore())
	sess, err := trans.Create(
		ctx,
		"google",
		session.OIDCStore(session.StepContinue, &session.OIDCFlow{OAuthState: "st"}).
			WithAuthContext(string(idpkg.IntentLinkAccount), linkUser.String()),
	)
	if err != nil {
		t.Fatalf("create transition: %v", err)
	}

	idm := idpkg.NewIdentityManager(trans, linkContinueStubProvider{})
	svc := NewService(Dependencies{
		IdentityManager: idm,
		TransitionStore: trans,
		Sessions:        &stubLinkSessionResolver{userID: linkUser},
	})

	op := &proofpb.OAuthProof{}
	op.SetCode("code")
	op.SetState("st")
	proof := &proofpb.AuthProof{}
	proof.SetOauthProof(op)

	req := &pb.ContinueAuthSessionRequest{}
	req.SetTransitionId(sess.Id)
	req.SetProof(proof)

	resp, err := svc.ContinueAuthSession(ctx, req, sess.Id, "wire-token")
	if err != nil {
		t.Fatalf("ContinueAuthSession: %v", err)
	}
	if resp.GetStatus() != basic.AuthStatus_AUTH_STATUS_CHALLENGE_REQUIRED {
		t.Fatalf("status: got %v", resp.GetStatus())
	}
}
