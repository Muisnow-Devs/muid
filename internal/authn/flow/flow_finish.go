package flow

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "sanzi.io/muid/api/proto/authn/v1"
	"sanzi.io/muid/api/proto/authn/v1/basic"
	sessionpb "sanzi.io/muid/api/proto/authn/v1/session"
	"sanzi.io/muid/internal/identity"
	"sanzi.io/muid/internal/session"
	grpcutils "sanzi.io/muid/pkg/grpc_utils"
	"sanzi.io/muid/pkg/log"
)

func (s *Service) finishAuthStep(
	ctx context.Context,
	req *pb.ContinueAuthSessionRequest,
	sess session.AuthSession,
	step identity.StepResult,
	tid string,
	linkSessionToken string,
) (*pb.ContinueAuthSessionResponse, error) {
	switch step.Type {
	case identity.StepLinked:
		return s.linkCompletedResponse(ctx, tid, linkSessionToken)
	case identity.StepAuthenticated:
		return s.authenticatedLoginResponse(ctx, tid, step.Authenticated)
	case identity.StepRegisterRequired:
		return s.completeRegisterRequired(ctx, req, sess, step, tid, linkSessionToken)
	default:
		log.LogUnexpected(ctx, "authn finish step", "unexpected terminal auth step")
		return nil, grpcutils.GRPCInternalError()
	}
}

func (s *Service) completeRegisterRequired(
	ctx context.Context,
	req *pb.ContinueAuthSessionRequest,
	sess session.AuthSession,
	step identity.StepResult,
	tid string,
	linkSessionToken string,
) (*pb.ContinueAuthSessionResponse, error) {
	uid, err := s.provisionRegisterRequired(ctx, step.RegisterRequired)
	if err != nil {
		return nil, err
	}

	store := sess.Store.WithProvisionedUserID(uid.String())
	err = s.transitionStore.Update(ctx, tid, store)
	if err != nil {
		log.LogUnexpected(ctx, "authn update transition after provision", err.Error())
		return nil, grpcutils.GRPCInternalError()
	}

	prov, err := s.idm.GetProvider(sess.Provider)
	if err != nil {
		log.LogUnexpected(ctx, "authn finish provider lookup", err.Error())
		return nil, grpcutils.GRPCInternalError()
	}

	finishStep, err := prov.Continue(ctx, identity.ContinueInput{
		TransitionId: tid,
		Payload: map[string]any{
			identity.ContinuePayloadFinishRegister: true,
		},
		LinkSessionToken: linkSessionToken,
	})
	if err != nil {
		return mapContinueError(ctx, tid, err)
	}

	return s.finishAuthStep(ctx, req, sess, finishStep, tid, linkSessionToken)
}

func (s *Service) provisionRegisterRequired(
	ctx context.Context,
	reg *identity.RegisterRequired,
) (uuid.UUID, error) {
	if reg == nil {
		log.LogUnexpected(
			ctx,
			"authn provision register required",
			"missing register-required data",
		)
		return uuid.Nil, grpcutils.GRPCInternalError()
	}

	uid, err := s.accounts.Provision.ProvisionUser(ctx, reg)
	if err != nil {
		log.LogUnexpected(ctx, "authn provision user", err.Error())
		return uuid.Nil, grpcutils.GRPCInternalError()
	}

	return uid, nil
}

func (s *Service) authenticatedLoginResponse(
	ctx context.Context,
	tid string,
	auth *identity.AuthenticatedIdentity,
) (*pb.ContinueAuthSessionResponse, error) {
	if auth == nil || strings.TrimSpace(auth.UserID) == "" {
		log.LogUnexpected(ctx, "authn authenticated response", "missing authenticated identity")
		return nil, grpcutils.GRPCInternalError()
	}

	uid, err := uuid.Parse(strings.TrimSpace(auth.UserID))
	if err != nil {
		log.LogUnexpected(ctx, "authn authenticated user id", err.Error())
		return nil, grpcutils.GRPCInternalError()
	}

	authResult, err := s.accounts.Session.IssueAuthenticatedSession(ctx, uid)
	if err != nil {
		log.LogUnexpected(ctx, "authn issue session", err.Error())
		return nil, grpcutils.GRPCInternalError()
	}

	resp := &pb.ContinueAuthSessionResponse{}
	resp.SetTransitionId(tid)
	resp.SetStatus(basic.AuthStatus_AUTH_STATUS_AUTHENTICATED)

	authOK := &sessionpb.AuthSuccess{}
	authOK.SetResult(authResult)
	resp.SetAuthSuccess(authOK)

	return resp, nil
}

func (s *Service) linkCompletedResponse(
	ctx context.Context,
	tid, wire string,
) (*pb.ContinueAuthSessionResponse, error) {
	resp := &pb.ContinueAuthSessionResponse{}
	resp.SetTransitionId(tid)
	resp.SetStatus(basic.AuthStatus_AUTH_STATUS_AUTHENTICATED)

	if wire == "" {
		return resp, nil
	}

	res, err := s.accounts.Session.ResolveSessionToken(ctx, wire)
	if errors.Is(err, session.ErrSessionNotFound) || errors.Is(err, session.ErrSessionExpired) {
		return nil, status.Error(codes.PermissionDenied, "valid session required")
	}
	if err != nil {
		log.LogUnexpected(ctx, "authn resolve linked session", err.Error())
		return nil, grpcutils.GRPCInternalError()
	}

	authOK := &sessionpb.AuthSuccess{}
	authOK.SetResult(s.accounts.Session.AuthenticatedResultFromResolved(wire, res))
	resp.SetAuthSuccess(authOK)

	return resp, nil
}
