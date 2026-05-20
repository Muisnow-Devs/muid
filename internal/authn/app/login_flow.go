package app

import (
	"context"
	"strings"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "sanzi.io/muid/api/proto/authn/v1"
	"sanzi.io/muid/api/proto/authn/v1/basic"
	sessionpb "sanzi.io/muid/api/proto/authn/v1/session"
	"sanzi.io/muid/internal/identity"
	"sanzi.io/muid/internal/session"
)

func (g *GRPCHandler) finishAuthStep(
	ctx context.Context,
	req *pb.ContinueAuthSessionRequest,
	sess session.AuthSession,
	step identity.StepResult,
) (*pb.ContinueAuthSessionResponse, error) {
	tid := strings.TrimSpace(req.GetTransitionId())
	wire := sessionTokenValue(req.GetSessionToken())

	switch step.Type {
	case identity.StepLinked:
		return g.linkCompletedResponse(ctx, tid, wire)
	case identity.StepAuthenticated:
		return g.authenticatedLoginResponse(ctx, tid, step.Authenticated)
	case identity.StepRegisterRequired:
		return g.completeRegisterRequired(ctx, req, sess, step)
	default:
		return nil, status.Error(codes.Internal, "unexpected terminal auth step")
	}
}

func (g *GRPCHandler) completeRegisterRequired(
	ctx context.Context,
	req *pb.ContinueAuthSessionRequest,
	sess session.AuthSession,
	step identity.StepResult,
) (*pb.ContinueAuthSessionResponse, error) {
	tid := strings.TrimSpace(req.GetTransitionId())

	uid, err := g.provisionRegisterRequired(ctx, step.RegisterRequired)
	if err != nil {
		return nil, err
	}

	store := sess.Store.WithProvisionedUserID(uid.String())
	err = g.transitionStore.Update(ctx, tid, store)
	if err != nil {
		return nil, status.Error(codes.Internal, "update transition after provision")
	}

	prov, err := g.idm.GetProvider(sess.Provider)
	if err != nil {
		return nil, status.Error(codes.Internal, "unknown transition provider")
	}

	finishStep, err := prov.Continue(ctx, identity.ContinueInput{
		TransitionId: tid,
		Payload: map[string]any{
			identity.ContinuePayloadFinishRegister: true,
		},
		LinkSessionToken: sessionTokenValue(req.GetSessionToken()),
	})
	if err != nil {
		return mapContinueError(tid, err)
	}

	return g.finishAuthStep(ctx, req, sess, finishStep)
}

func (g *GRPCHandler) provisionRegisterRequired(
	ctx context.Context,
	reg *identity.RegisterRequired,
) (uuid.UUID, error) {
	if reg == nil {
		return uuid.Nil, status.Error(codes.Internal, "missing register-required data")
	}

	uid, err := g.accounts.Provision.ProvisionUser(ctx, reg)
	if err != nil {
		return uuid.Nil, err
	}

	return uid, nil
}

func (g *GRPCHandler) authenticatedLoginResponse(
	ctx context.Context,
	tid string,
	auth *identity.AuthenticatedIdentity,
) (*pb.ContinueAuthSessionResponse, error) {
	if auth == nil || strings.TrimSpace(auth.UserID) == "" {
		return nil, status.Error(codes.Internal, "missing authenticated identity")
	}

	uid, err := uuid.Parse(strings.TrimSpace(auth.UserID))
	if err != nil {
		return nil, status.Error(codes.Internal, "invalid authenticated user id")
	}

	authResult, err := g.accounts.Session.IssueAuthenticatedSession(ctx, uid)
	if err != nil {
		return nil, err
	}

	resp := &pb.ContinueAuthSessionResponse{}
	resp.SetTransitionId(tid)
	resp.SetStatus(basic.AuthStatus_AUTH_STATE_AUTHENTICATED)

	authOK := &sessionpb.AuthSuccess{}
	authOK.SetResult(authResult)
	resp.SetAuthSuccess(authOK)

	return resp, nil
}

func (g *GRPCHandler) linkCompletedResponse(
	ctx context.Context,
	tid, wire string,
) (*pb.ContinueAuthSessionResponse, error) {
	resp := &pb.ContinueAuthSessionResponse{}
	resp.SetTransitionId(tid)
	resp.SetStatus(basic.AuthStatus_AUTH_STATE_AUTHENTICATED)

	if wire == "" {
		return resp, nil
	}

	res, err := g.accounts.Session.ResolveSessionToken(ctx, wire)
	if err != nil {
		return nil, err
	}

	authOK := &sessionpb.AuthSuccess{}
	authOK.SetResult(g.accounts.Session.AuthenticatedResultFromResolved(wire, res))
	resp.SetAuthSuccess(authOK)

	return resp, nil
}
