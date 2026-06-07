package authngrpc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "sanzi.io/muid/api/proto/authn/v1"
	basicpb "sanzi.io/muid/api/proto/authn/v1/basic"
	challengepb "sanzi.io/muid/api/proto/authn/v1/challenge"
	sessionpb "sanzi.io/muid/api/proto/authn/v1/session"
	"sanzi.io/muid/internal/identity/issuer"
	"sanzi.io/muid/internal/identity/method"
	"sanzi.io/muid/internal/identity/policy"
	identitystore "sanzi.io/muid/internal/identity/store"
	"sanzi.io/muid/internal/session"
	"sanzi.io/muid/pkg/clientmeta"
	"sanzi.io/muid/pkg/errutil"
	grpcutils "sanzi.io/muid/pkg/grpc_utils"
	"sanzi.io/muid/pkg/log"
	"sanzi.io/muid/pkg/shared/authn"
)

func (g *GRPCHandler) StartAuthSession(
	ctx context.Context,
	req *pb.StartAuthSessionRequest,
) (*pb.StartAuthSessionResponse, error) {
	intent := req.GetIntent()
	if intent == basicpb.AuthIntent_AUTH_INTENT_UNSPECIFIED {
		return nil, status.Error(codes.InvalidArgument, "missing auth intent")
	}

	var sessionIntent session.AuthIntent
	switch intent {
	case basicpb.AuthIntent_AUTH_INTENT_LOGIN:
		sessionIntent = session.AuthIntentLogin
	case basicpb.AuthIntent_AUTH_INTENT_LINK_ACCOUNT:
		sessionIntent = session.AuthIntentLinkAccount
	case basicpb.AuthIntent_AUTH_INTENT_REAUTHENTICATE:
		sessionIntent = session.AuthIntentReauth
	}

	// For link_account / reauth: session token must be present in the authorization header.
	var currentSession *issuer.ResolvedSession
	if intent == basicpb.AuthIntent_AUTH_INTENT_LINK_ACCOUNT ||
		intent == basicpb.AuthIntent_AUTH_INTENT_REAUTHENTICATE {
		wire, ok := grpcutils.WireSessionTokenFromContext(ctx)
		if !ok {
			return nil, status.Error(codes.PermissionDenied, "action requires valid session")
		}
		sess, err := g.issuer.ResolveSessionToken(ctx, wire)
		if err != nil {
			return nil, status.Error(codes.PermissionDenied, "valid session required")
		}
		currentSession = &sess
	}

	meta, _ := clientmeta.FromContext(ctx)
	reqMeta := session.SessionMetadata{
		Locale:    meta.Locale,
		Timezone:  meta.Timezone,
		UserAgent: meta.UserAgent,
		IPAddress: meta.IPAddress,
		Location:  meta.Location,
		Device:    meta.Device,
	}

	startReq := method.StartRequest{
		Identifier: req.GetIdentifier(),
	}

	var operationUserID *uuid.UUID
	if currentSession != nil {
		operationUserID = &currentSession.UserID
	}

	sessionStore := session.SessionStore{
		Step:            session.StepStart,
		Intent:          sessionIntent,
		OperationUserID: operationUserID,
		Metadata:        reqMeta,
	}

	// Resolve the method — the only place where auth method type drives a branch.
	idm, err := g.resolveMethod(req)
	if err != nil {
		return nil, err
	}

	step, err := idm.Start(ctx, sessionStore, startReq)
	if err != nil {
		return nil, err
	}

	return g.combineStartResponse(step, req.GetIdentifier())
}

func (g *GRPCHandler) resolveMethod(
	req *pb.StartAuthSessionRequest,
) (method.IdentityMethod, error) {
	switch req.GetMethod() {
	case basicpb.AuthMethod_AUTH_METHOD_EMAIL_OTP:
		p, err := g.identityManager.GetProvider("email")
		return p.Method, err
	case basicpb.AuthMethod_AUTH_METHOD_OAUTH:
		provider := strings.ToLower(strings.TrimSpace(req.GetIdentifier()))
		p, err := g.identityManager.GetProvider(provider)
		return p.Method, err
	case basicpb.AuthMethod_AUTH_METHOD_PASSKEY:
		p, err := g.identityManager.GetProvider("passkey")
		return p.Method, err
	default:
		return nil, status.Errorf(
			codes.InvalidArgument,
			"unsupported auth method %v",
			req.GetMethod(),
		)
	}
}

func (g *GRPCHandler) ContinueAuthSession(
	ctx context.Context,
	req *pb.ContinueAuthSessionRequest,
) (*pb.ContinueAuthSessionResponse, error) {
	tidStr := req.GetTransitionId()
	tid, err := uuid.Parse(tidStr)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid transition id")
	}

	sess, err := g.transitionStore.Get(ctx, tid)
	switch {
	case errors.Is(err, session.ErrSessionValidationFailed):
		g.transitionStore.Delete(ctx, tid)
		return nil, status.Error(codes.InvalidArgument, "invalid transition state")
	case err != nil:
		log.LogUnexpected(ctx, "get auth session transition", err.Error())
		return nil, grpcutils.GRPCInternalError()
	}

	// For link_account flows: the existing user session comes from the authorization header.
	var resolvedSession *issuer.ResolvedSession
	wire, ok := grpcutils.WireSessionTokenFromContext(ctx)
	if ok {
		rs, err := g.issuer.ResolveSessionToken(ctx, wire)
		if err != nil {
			return nil, status.Error(codes.PermissionDenied, "valid session required")
		}
		resolvedSession = &rs
	}

	if sess.Store.Intent != session.AuthIntentLogin &&
		(resolvedSession == nil || sess.Store.OperationUserID == nil || *sess.Store.OperationUserID != resolvedSession.UserID) {
		return nil, status.Error(codes.PermissionDenied, "session user mismatch")
	}

	continueReq := method.ContinueRequest{
		TransitionID: tid,
		Session:      resolvedSession,
	}

	step, contErr := g.verifyProof(ctx, req, sess, continueReq)
	if contErr != nil {
		return nil, contErr
	}

	switch s := step.(type) {
	case *method.FailureStep:
		g.transitionStore.Delete(ctx, tid)
		return continueAuthFailure(tid, s.Message, s.Code), nil

	case method.ChallengeStep:
		cr := &sessionpb.ChallengeRequired{}
		ch := g.buildAuthChallenge(s.TransitionID.String(), s.Challenge)
		cr.SetChallenge(ch)

		resp := &pb.ContinueAuthSessionResponse{}
		resp.SetTransitionId(tidStr)
		resp.SetStatus(basicpb.AuthStatus_AUTH_STATUS_CHALLENGE_REQUIRED)
		resp.SetChallengeRequired(cr)
		return resp, nil

	case *method.VerifiedStep:
		return g.handleVerifiedStep(ctx, tid, wire, s)

	default:
		log.LogUnexpected(ctx, "continue auth session", "unexpected step type", slog.Any("type", fmt.Sprintf("%T", step)))
		return nil, status.Error(codes.Internal, "internal error")
	}
}

// verifyProof dispatches the continuation payload to the correct method.
// The proto proof type determines the method; payload construction is done here
// so that handleVerifiedStep sees only the unified VerifiedStep — no type switch.
func (g *GRPCHandler) verifyProof(
	ctx context.Context,
	req *pb.ContinueAuthSessionRequest,
	transition session.AuthSession,
	continueReq method.ContinueRequest,
) (method.Step, error) {
	proof := req.GetProof()
	if proof == nil {
		return nil, status.Error(codes.InvalidArgument, "missing proof")
	}

	var idm method.IdentityMethod

	switch {
	case proof.GetEmailProof() != nil:
		ep := proof.GetEmailProof()
		p, err := g.identityManager.GetProvider("email")
		if err != nil {
			log.LogUnexpected(ctx, "get email provider", err.Error())
			return nil, status.Error(codes.Internal, "internal error")
		}
		idm = p.Method
		if ep.GetOtpCode() != "" {
			continueReq.Payload = method.EmailOTPCodePayload{Code: ep.GetOtpCode()}
		} else if ep.HasResend() {
			continueReq.Payload = method.EmailOTPResendPayload{}
		} else {
			return nil, status.Error(codes.InvalidArgument, "invalid email proof")
		}

	case proof.GetOauthProof() != nil:
		op := proof.GetOauthProof()
		continueReq.Payload = method.OIDCCallbackPayload{Code: op.GetCode(), State: op.GetState()}
		provider := strings.ToLower(transition.Provider)
		p, err := g.identityManager.GetProvider(provider)
		if err != nil {
			return nil, status.Errorf(
				codes.InvalidArgument,
				"unsupported OIDC provider %q",
				transition.Provider,
			)
		}
		idm = p.Method

	case proof.GetPasskeyProof() != nil:
		pp := proof.GetPasskeyProof()
		p, err := g.identityManager.GetProvider("passkey")
		if err != nil {
			log.LogUnexpected(ctx, "get passkey provider", err.Error())
			return nil, status.Error(codes.Internal, "internal error")
		}
		idm = p.Method
		if pp.GetCredentialCreationResponseJson() != "" {
			continueReq.Payload = method.PasskeyCreationPayload{
				CredentialCreationResponseJSON: pp.GetCredentialCreationResponseJson(),
			}
		} else if pp.GetCredentialAssertionResponseJson() != "" {
			continueReq.Payload = method.PasskeyAssertionPayload{
				CredentialAssertionResponseJSON: pp.GetCredentialAssertionResponseJson(),
			}
		} else {
			return nil, status.Error(codes.InvalidArgument, "invalid passkey proof")
		}

	default:
		return nil, status.Error(codes.InvalidArgument, "unsupported proof type")
	}

	step, err := idm.Continue(ctx, continueReq)
	if err != nil {
		log.LogUnexpected(ctx, "authn continue proof verification", err.Error())
		return nil, status.Error(codes.Internal, "failed to verify proof")
	}
	return step, nil
}

// handleVerifiedStep is the unified post-verification flow. All auth intents
// converge here and produce the same result: an issued session token.
func (g *GRPCHandler) handleVerifiedStep(
	ctx context.Context,
	tid uuid.UUID,
	wire string,
	s *method.VerifiedStep,
) (*pb.ContinueAuthSessionResponse, error) {
	transitionData, err := g.transitionStore.Get(ctx, tid)
	if err != nil {
		return nil, status.Error(codes.NotFound, "transition not found")
	}
	g.transitionStore.Delete(ctx, tid)

	reqMeta := transitionData.Store.Metadata

	// Retrieve the per-method provider (method + store) by provider name.
	provider, err := g.identityManager.GetProvider(s.Provider)
	if err != nil {
		log.LogUnexpected(ctx, "get identity provider", err.Error())
		return nil, status.Error(codes.Internal, "internal error")
	}
	store := provider.Store

	// Look up any existing identity for this provider+subject.
	identityRecord, err := store.FindUser(ctx, s.Provider, s.Subject)
	if err != nil {
		log.LogUnexpected(ctx, "find identity", err.Error())
		return nil, status.Error(codes.Internal, "internal error")
	}

	// Determine the user ID — the only intent-driven branch in the flow.
	userID, authFailure, err := g.resolveUserID(ctx, tid, transitionData, identityRecord, s)
	if err != nil {
		log.LogUnexpected(ctx, "resolve user id", err.Error())
		return nil, status.Error(codes.Internal, "internal error")
	}
	if authFailure != nil {
		return authFailure, nil
	}

	// Link identity when it is not yet persisted.
	if identityRecord == nil {
		if _, err = store.LinkIdentity(ctx, userID, s.Identity.IdentityClaims); err != nil {
			if errors.Is(err, identitystore.ErrCredentialAlreadyRegistered) {
				return continueAuthFailure(
					tid,
					"This passkey is already registered.",
					authn.ErrCodePasskeyAlreadyRegistered,
				), nil
			}
			log.LogUnexpected(ctx, "link identity", err.Error())
			return nil, status.Error(codes.Internal, "internal error")
		}
	} else {
		// Best-effort: update last-used timestamp on an existing identity.
		errutil.Discard(store.UpdateLastUsed(ctx, identityRecord.ID))
	}

	if wire != "" {
		errutil.Discard(g.issuer.RevokeSessionToken(ctx, wire))
	}

	// All intents end with an issued session.
	authResult, err := g.issuer.CreateSession(ctx, userID, transitionData.Store.Metadata)
	if err != nil {
		return nil, err
	}

	g.dispatchAuthNotification(ctx, transitionData.Store.Intent, userID, s.Provider, reqMeta)
	return continueAuthSuccess(tid, authResult), nil
}

// resolveUserID determines which user the verified identity belongs to,
// enforcing policy for link-account requests.
func (g *GRPCHandler) resolveUserID(
	ctx context.Context,
	tid uuid.UUID,
	transitionData session.AuthSession,
	identityRecord *identitystore.Identity,
	s *method.VerifiedStep,
) (uuid.UUID, *pb.ContinueAuthSessionResponse, error) {
	switch transitionData.Store.Intent {
	case session.AuthIntentLinkAccount:
		if transitionData.Store.OperationUserID == nil {
			return uuid.Nil, nil, errors.New("link_account transition missing operation user id")
		}
		linkUserID := *transitionData.Store.OperationUserID

		decision, err := g.policy.ValidateLink(ctx, policy.LinkRequest{
			Provider: s.Provider,
			Subject:  s.Subject,
		})
		if err != nil {
			return uuid.Nil, nil, err
		}
		if decision == policy.LinkDecisionReject {
			return uuid.Nil, continueAuthFailure(
				tid,
				"That identity is already in use.",
				authn.ErrCodeEmailAlreadyInUse,
			), nil
		}
		return linkUserID, nil, nil

	default: // AuthIntentLogin, AuthIntentReauth
		if identityRecord != nil {
			return identityRecord.UserID, nil, nil
		}
		// First-time login: resolve (find or create) the user account from claims.
		res, err := g.resolver.ResolveUser(ctx, s.Identity.UserClaims)
		if err != nil {
			return uuid.Nil, nil, err
		}
		return res.UserID, nil, nil
	}
}

// dispatchAuthNotification fires side-effect notifications after a successful auth.
func (g *GRPCHandler) dispatchAuthNotification(
	ctx context.Context,
	intent session.AuthIntent,
	userID uuid.UUID,
	provider string,
	meta session.SessionMetadata,
) {
	switch intent {
	case session.AuthIntentLinkAccount:
		g.notifyAccountLinked(ctx, userID, provider, meta)
	default:
		g.notifyLoginCompleted(ctx, userID, meta)
	}
}

func (g *GRPCHandler) buildAuthChallenge(
	tid string,
	challenge any,
) *challengepb.AuthChallenge {
	ch := &challengepb.AuthChallenge{}
	ch.SetChallengeId(tid)
	ch.SetIssuedAt(timestamppb.New(time.Now()))
	ch.SetExpiresAt(timestamppb.New(time.Now().Add(15 * time.Minute)))

	switch payload := challenge.(type) {
	case *method.EmailOTPChallenge:
		ec := &challengepb.EmailChallenge{}
		ec.SetEmailMasked(payload.MaskedEmail)
		ec.SetResendCooldownMillis(payload.Cooldown.Milliseconds())
		ch.SetEmailChallenge(ec)

	case *method.PasskeyChallengePayload:
		pc := &challengepb.PasskeyChallenge{}
		pc.SetState(tid)
		pc.SetTimeoutMillis(payload.TimeoutMillis)
		if payload.Ceremony == "registration" {
			pc.SetCeremony(challengepb.PasskeyCeremony_PASSKEY_CEREMONY_REGISTRATION)
			pc.SetPublicKeyCredentialCreationOptionsJson(payload.PublicKeyCredentialCreationOptionsJSON)
		} else {
			pc.SetCeremony(challengepb.PasskeyCeremony_PASSKEY_CEREMONY_AUTHENTICATION)
			pc.SetPublicKeyCredentialRequestOptionsJson(payload.PublicKeyCredentialRequestOptionsJSON)
		}
		ch.SetPasskeyChallenge(pc)
	}

	return ch
}

func (g *GRPCHandler) combineStartResponse(
	step method.Step,
	identifier string,
) (*pb.StartAuthSessionResponse, error) {
	if stepFailure, ok := step.(*method.FailureStep); ok {
		return nil, status.Error(codes.InvalidArgument, stepFailure.Message)
	}

	resp := &pb.StartAuthSessionResponse{}
	switch s := step.(type) {
	case method.ChallengeStep:
		resp.SetTransitionId(s.TransitionID.String())
		resp.SetChallenge(g.buildAuthChallenge(s.TransitionID.String(), s.Challenge))

	case method.RedirectStep:
		resp.SetTransitionId(s.TransitionID.String())

		ch := &challengepb.AuthChallenge{}
		ch.SetChallengeId(s.TransitionID.String())
		ch.SetIssuedAt(timestamppb.New(time.Now()))
		ch.SetExpiresAt(timestamppb.New(time.Now().Add(15 * time.Minute)))

		oc := &challengepb.OAuthChallenge{}
		oc.SetProvider(identifier)
		oc.SetAuthUrl(s.RedirectURL)
		ch.SetOauthChallenge(oc)
		resp.SetChallenge(ch)
	}

	return resp, nil
}
