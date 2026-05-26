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
	"sanzi.io/muid/internal/authn/account"
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
		return s.linkCompletedResponse(ctx, tid, strings.TrimSpace(linkSessionToken))
	case identity.StepAuthenticated:
		return s.authenticatedLoginResponse(ctx, tid, step.Authenticated, step.LoginCompletion)
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
	uid, existingUser, err := s.resolveRegisterRequired(
		ctx,
		tid,
		sess,
		step.RegisterRequired,
		linkSessionToken,
	)
	if err != nil {
		resp, mapErr := s.mapContinueError(ctx, tid, err)
		if mapErr != nil {
			return nil, mapErr
		}
		return resp, nil
	}

	sess, err = s.transitionStore.Get(ctx, tid)
	if err != nil {
		log.LogUnexpected(ctx, "authn finish reload transition", err.Error())
		return nil, grpcutils.GRPCInternalError()
	}
	err = s.transitionStore.Update(ctx, tid, sess.Store.WithRegisterResolution(existingUser))
	if err != nil {
		log.LogUnexpected(ctx, "authn finish persist register resolution", err.Error())
		return nil, grpcutils.GRPCInternalError()
	}

	prov, err := s.idm.GetProvider(sess.Provider)
	if err != nil {
		log.LogUnexpected(ctx, "authn finish provider lookup", err.Error())
		return nil, grpcutils.GRPCInternalError()
	}

	finishStep, err := prov.Continue(ctx, identity.ContinueInput{
		TransitionId:     tid,
		ContinueState:    identity.ContinueStateFinishRegister,
		FinishRegister:   &identity.FinishRegisterInput{RegisteredUserID: uid},
		LinkSessionToken: linkSessionToken,
	})
	if err != nil {
		return s.mapContinueError(ctx, tid, err)
	}

	return s.finishAuthStep(ctx, req, sess, finishStep, tid, linkSessionToken)
}

func (s *Service) authenticatedLoginResponse(
	ctx context.Context,
	tid string,
	auth *identity.AuthenticatedIdentity,
	completion *identity.LoginCompletionContext,
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

	authResult, err := s.sessions.IssueAuthenticatedSession(ctx, uid)
	if err != nil {
		log.LogUnexpected(ctx, "authn issue session", err.Error())
		return nil, grpcutils.GRPCInternalError()
	}

	completion = s.loginCompletionForAlert(ctx, tid, completion)

	s.cleanTransition(ctx, tid)

	resp := &pb.ContinueAuthSessionResponse{}
	resp.SetTransitionId(tid)
	resp.SetStatus(basic.AuthStatus_AUTH_STATUS_AUTHENTICATED)

	authOK := &sessionpb.AuthSuccess{}
	authOK.SetResult(authResult)
	resp.SetAuthSuccess(authOK)

	s.notifyLoginCompleted(ctx, uid, completion)

	return resp, nil
}

func (s *Service) notifyLoginCompleted(
	ctx context.Context,
	uid uuid.UUID,
	completion *identity.LoginCompletionContext,
) {
	if s.notifier == nil {
		return
	}

	err := s.notifier.NotifyLoginCompleted(
		ctx,
		uid,
		mailDeliveryPrefs(completion),
		loginAlertDetails(completion),
	)
	if err != nil {
		log.LogUnexpected(ctx, "authn publish login alert", err.Error())
	}
}

func mailDeliveryPrefs(completion *identity.LoginCompletionContext) account.MailDeliveryPrefs {
	if completion == nil {
		return account.MailDeliveryPrefs{}
	}
	return account.MailDeliveryPrefs{
		Locale:   completion.Locale,
		Timezone: completion.Timezone,
	}
}

func (s *Service) loginCompletionForAlert(
	ctx context.Context,
	tid string,
	completion *identity.LoginCompletionContext,
) *identity.LoginCompletionContext {
	var fromStep session.MailClientContext
	if completion != nil {
		fromStep = session.MailClientContext{
			Locale:    completion.Locale,
			Timezone:  completion.Timezone,
			Device:    completion.Device,
			Location:  completion.Location,
			UserAgent: completion.UserAgent,
			IPAddress: completion.IPAddress,
		}
	}

	sess, err := s.transitionStore.Get(ctx, tid)
	if err != nil {
		if !errors.Is(err, session.ErrSessionNotFound) {
			log.LogUnexpected(ctx, "authn login alert load transition", err.Error())
		}
		if completion == nil {
			return nil
		}
		return completion
	}

	merged := session.MergeMailClientContext(sess.Store.MailClientContext(), fromStep)
	return &identity.LoginCompletionContext{
		Locale:    merged.Locale,
		Timezone:  merged.Timezone,
		Device:    merged.Device,
		Location:  merged.Location,
		UserAgent: merged.UserAgent,
		IPAddress: merged.IPAddress,
	}
}

func loginAlertDetails(completion *identity.LoginCompletionContext) account.LoginAlertDetails {
	if completion == nil {
		return account.LoginAlertDetails{}
	}
	return account.LoginAlertDetails{
		IPAddress: completion.IPAddress,
		Location:  completion.Location,
		Device:    completion.Device,
		UserAgent: completion.UserAgent,
	}
}

func (s *Service) linkCompletedResponse(
	ctx context.Context,
	tid, wire string,
) (*pb.ContinueAuthSessionResponse, error) {
	sess, err := s.transitionStore.Get(ctx, tid)
	if err != nil && !errors.Is(err, session.ErrSessionNotFound) {
		log.LogUnexpected(ctx, "authn link complete load transition", err.Error())
		return nil, grpcutils.GRPCInternalError()
	}
	linkUserID := ""
	linkProvider := ""
	linkMailPrefs := account.MailDeliveryPrefs{}
	if err == nil {
		_, linkUserID, _ = sess.Store.AuthContext()
		linkProvider = strings.TrimSpace(sess.Provider)
		linkMailPrefs = account.MailDeliveryPrefs{
			Locale:   sess.Store.Locale,
			Timezone: sess.Store.Timezone,
		}
		valErr := s.validateLinkContinueSession(ctx, sess, wire)
		if valErr != nil {
			return s.mapContinueError(ctx, tid, valErr)
		}
	}

	wire = strings.TrimSpace(wire)

	s.cleanTransition(ctx, tid)

	resp := &pb.ContinueAuthSessionResponse{}
	resp.SetTransitionId(tid)
	resp.SetStatus(basic.AuthStatus_AUTH_STATUS_AUTHENTICATED)

	if wire == "" {
		return resp, nil
	}

	res, err := s.sessions.ResolveSessionToken(ctx, wire)
	if errors.Is(err, session.ErrSessionNotFound) || errors.Is(err, session.ErrSessionExpired) {
		return nil, status.Error(codes.PermissionDenied, "valid session required")
	}
	if err != nil {
		log.LogUnexpected(ctx, "authn resolve linked session", err.Error())
		return nil, grpcutils.GRPCInternalError()
	}

	if linkUserID != "" {
		expected, parseErr := uuid.Parse(strings.TrimSpace(linkUserID))
		if parseErr != nil {
			log.LogUnexpected(ctx, "authn link complete user id", parseErr.Error())
			return nil, grpcutils.GRPCInternalError()
		}
		if res.UserID != expected {
			return nil, status.Error(codes.PermissionDenied, "valid session required")
		}
	}

	err = s.sessions.RevokeSessionToken(ctx, wire)
	if err != nil && !errors.Is(err, session.ErrSessionNotFound) {
		log.LogUnexpected(ctx, "authn revoke link session", err.Error())
		return nil, grpcutils.GRPCInternalError()
	}

	authResult, err := s.sessions.IssueAuthenticatedSession(ctx, res.UserID)
	if err != nil {
		log.LogUnexpected(ctx, "authn issue linked session", err.Error())
		return nil, grpcutils.GRPCInternalError()
	}

	authOK := &sessionpb.AuthSuccess{}
	authOK.SetResult(authResult)
	resp.SetAuthSuccess(authOK)

	s.notifyAccountLinked(ctx, res.UserID, linkProvider, linkMailPrefs)

	return resp, nil
}

func (s *Service) notifyAccountLinked(
	ctx context.Context,
	userID uuid.UUID,
	provider string,
	mailPrefs account.MailDeliveryPrefs,
) {
	if s.notifier == nil {
		return
	}

	err := s.notifier.NotifyAccountLinked(ctx, userID, provider, mailPrefs)
	if err != nil {
		log.LogUnexpected(ctx, "authn publish account linked", err.Error())
	}
}
