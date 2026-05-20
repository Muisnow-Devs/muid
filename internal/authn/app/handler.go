package app

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "sanzi.io/muid/api/proto/authn/v1"
	"sanzi.io/muid/api/proto/authn/v1/basic"
	"sanzi.io/muid/api/proto/authn/v1/challenge"
	proofpb "sanzi.io/muid/api/proto/authn/v1/proof"
	sessionpb "sanzi.io/muid/api/proto/authn/v1/session"
	"sanzi.io/muid/internal/authn/infra/account"
	implIdentity "sanzi.io/muid/internal/authn/infra/identity"
	"sanzi.io/muid/internal/identity"
	"sanzi.io/muid/internal/otp"
	"sanzi.io/muid/internal/session"
)

type GRPCHandler struct {
	pb.UnimplementedAuthnServiceServer

	optStore                otp.OTPStore
	idm                     *identity.IdentityManager
	transitionStore         session.AuthTransitionStore
	accounts                *account.Accounts
	otpResendCooldownMillis int64
}

func CreateGRPCHandler(infra *InfraDependencies) pb.AuthnServiceServer {
	cooldownSec := infra.GlobalConfig.OTPSendCooldownSeconds
	if cooldownSec < 0 {
		cooldownSec = 0
	}
	return &GRPCHandler{
		optStore:                infra.OTPStore,
		idm:                     infra.IdentityManager,
		transitionStore:         infra.TransitionStore,
		accounts:                infra.Accounts,
		otpResendCooldownMillis: int64(cooldownSec) * 1000,
	}
}

func (g *GRPCHandler) StartAuthSession(
	ctx context.Context,
	req *pb.StartAuthSessionRequest,
) (*pb.StartAuthSessionResponse, error) {
	providerName, err := providerNameForMethod(
		req.GetMethod(),
		strings.TrimSpace(req.GetIdentifier()),
	)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	prov, err := g.idm.GetProvider(providerName)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	step, err := prov.Start(ctx, identity.StartInput{
		Provider:         providerName,
		Identifier:       strings.TrimSpace(req.GetIdentifier()),
		Intent:           protoIntent(req.GetIntent()),
		LinkSessionToken: sessionTokenValue(req.GetSessionToken()),
	})
	if err != nil {
		return nil, mapStartError(err)
	}

	sess, err := g.transitionStore.Get(ctx, step.TransitionId)
	if err != nil {
		return nil, status.Error(codes.Internal, "load transition after start")
	}

	ch, err := buildAuthChallenge(req.GetMethod(), sess, step, g.otpResendCooldownMillis)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	out := &pb.StartAuthSessionResponse{}
	out.SetTransitionId(step.TransitionId)
	out.SetChallenge(ch)
	return out, nil
}

func (g *GRPCHandler) ContinueAuthSession(
	ctx context.Context,
	req *pb.ContinueAuthSessionRequest,
) (*pb.ContinueAuthSessionResponse, error) {
	tid := strings.TrimSpace(req.GetTransitionId())
	sess, err := g.transitionStore.Get(ctx, tid)
	if err != nil {
		if errors.Is(err, session.ErrSessionNotFound) {
			return nil, status.Error(codes.NotFound, "transition not found")
		}
		if errors.Is(err, session.ErrSessionExpired) {
			return nil, status.Error(codes.FailedPrecondition, "transition expired")
		}
		return nil, err
	}

	prov, err := g.idm.GetProvider(sess.Provider)
	if err != nil {
		return nil, status.Error(codes.Internal, "unknown transition provider")
	}

	payload, err := proofToPayload(req.GetProof())
	if err != nil {
		return nil, err
	}

	step, err := prov.Continue(ctx, identity.ContinueInput{
		TransitionId:     tid,
		Payload:          payload,
		LinkSessionToken: sessionTokenValue(req.GetSessionToken()),
	})
	if err != nil {
		return mapContinueError(tid, err)
	}

	if step.Type == identity.StepInput {
		return g.continueAwaitingChallenge(tid, sess, step)
	}

	return g.finishAuthStep(ctx, req, sess, step)
}

func providerNameForMethod(m basic.AuthMethod, identifier string) (string, error) {
	switch m {
	case basic.AuthMethod_AUTH_METHOD_EMAIL_OTP:
		return "email", nil
	case basic.AuthMethod_AUTH_METHOD_OAUTH:
		if identifier == "" {
			return "", fmt.Errorf("oauth method requires identifier (provider name, e.g. google)")
		}
		return strings.ToLower(identifier), nil
	case basic.AuthMethod_AUTH_METHOD_PASSKEY:
		return "passkey", nil
	default:
		return "", fmt.Errorf("unsupported auth method %v", m)
	}
}

func buildAuthChallenge(
	method basic.AuthMethod,
	sess session.AuthSession,
	step identity.StepResult,
	otpResendCooldownMillis int64,
) (*challenge.AuthChallenge, error) {
	now := time.Now()
	ch := &challenge.AuthChallenge{}
	ch.SetChallengeId(step.TransitionId)
	ch.SetIssuedAt(timestamppb.New(now))
	ch.SetExpiresAt(timestamppb.New(now.Add(15 * time.Minute)))

	switch method {
	case basic.AuthMethod_AUTH_METHOD_EMAIL_OTP:
		emailFlow, ok := sess.Store.EmailFlow()
		if !ok {
			return nil, fmt.Errorf("missing email transition data")
		}
		ec := &challenge.EmailChallenge{}
		ec.SetEmailMasked(maskEmail(emailFlow.Email))
		ec.SetResendCooldownMillis(otpResendCooldownMillis)
		ch.SetEmailChallenge(ec)
	case basic.AuthMethod_AUTH_METHOD_OAUTH:
		oc := &challenge.OAuthChallenge{}
		oc.SetProvider(sess.Provider)
		oc.SetAuthUrl(step.RedirectURL)
		ch.SetOauthChallenge(oc)
	case basic.AuthMethod_AUTH_METHOD_PASSKEY:
		pc := &challenge.PasskeyChallenge{}
		pc.SetState(step.TransitionId)
		if step.Payload != nil && step.Payload.Passkey != nil {
			pk := step.Payload.Passkey
			pc.SetPublicKeyCredentialRequestOptionsJson(
				pk.PublicKeyCredentialRequestOptionsJSON,
			)
			pc.SetTimeoutMillis(pk.TimeoutMillis)
		}
		ch.SetPasskeyChallenge(pc)
	default:
		return nil, fmt.Errorf("unsupported method for challenge mapping")
	}
	return ch, nil
}

func authMethodForProvider(provider string) (basic.AuthMethod, error) {
	switch provider {
	case "email":
		return basic.AuthMethod_AUTH_METHOD_EMAIL_OTP, nil
	case "passkey":
		return basic.AuthMethod_AUTH_METHOD_PASSKEY, nil
	default:
		if provider == "" {
			return basic.AuthMethod_AUTH_METHOD_UNSPECIFIED, fmt.Errorf(
				"missing transition provider",
			)
		}
		return basic.AuthMethod_AUTH_METHOD_OAUTH, nil
	}
}

func (g *GRPCHandler) continueAwaitingChallenge(
	tid string,
	sess session.AuthSession,
	step identity.StepResult,
) (*pb.ContinueAuthSessionResponse, error) {
	if strings.TrimSpace(step.TransitionId) != "" && step.TransitionId != tid {
		return nil, status.Error(codes.Internal, "transition mismatch after continue")
	}

	method, err := authMethodForProvider(sess.Provider)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	ch, err := buildAuthChallenge(method, sess, step, g.otpResendCooldownMillis)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	cr := &sessionpb.ChallengeRequired{}
	cr.SetChallenge(ch)

	out := &pb.ContinueAuthSessionResponse{}
	out.SetTransitionId(tid)
	out.SetStatus(basic.AuthStatus_AUTH_STATE_CHALLENGE_REQUIRED)
	out.SetChallengeRequired(cr)
	return out, nil
}

func maskEmail(email string) string {
	email = strings.TrimSpace(email)
	at := strings.LastIndex(email, "@")
	if at <= 0 || at == len(email)-1 {
		return "***"
	}
	local, dom := email[:at], email[at+1:]
	if len(local) <= 2 {
		return "**@" + dom
	}
	return local[:1] + "***" + local[len(local)-1:] + "@" + dom
}

func proofToPayload(proof *proofpb.AuthProof) (map[string]any, error) {
	if proof == nil {
		return nil, status.Error(codes.InvalidArgument, "missing proof")
	}
	if ep := proof.GetEmailProof(); ep != nil {
		payload, err := implIdentity.EmailProofToPayload(ep)
		if err == nil {
			return payload, nil
		}
		if errors.Is(err, identity.ErrInvalidInput) {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		return nil, status.Error(codes.Internal, err.Error())
	}
	if op := proof.GetOauthProof(); op != nil {
		return map[string]any{
			implIdentity.OIDCPayloadKeyCode:  op.GetCode(),
			implIdentity.OIDCPayloadKeyState: op.GetState(),
		}, nil
	}
	if pp := proof.GetPasskeyProof(); pp != nil {
		out := map[string]any{}
		if s := pp.GetCredentialAssertionResponseJson(); s != "" {
			out["credential_assertion_response_json"] = s
		}
		if s := pp.GetCredentialCreationResponseJson(); s != "" {
			out["credential_creation_response_json"] = s
		}
		if len(out) == 0 {
			return nil, status.Error(codes.InvalidArgument, "passkey proof missing credential json")
		}
		return out, nil
	}
	return nil, status.Error(codes.InvalidArgument, "unsupported proof type")
}

func mapStartError(err error) error {
	switch {
	case errors.Is(err, identity.ErrInvalidInput):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, otp.ErrOTPSendRateLimited):
		return status.Error(codes.ResourceExhausted, "OTP send rate limited; try again later")
	case errors.Is(err, identity.ErrLinkUnauthorized):
		return status.Error(codes.PermissionDenied, "valid session required")
	case errors.Is(err, identity.ErrEmailAlreadyInUse):
		return status.Error(codes.AlreadyExists, "email already in use")
	default:
		return status.Error(codes.Internal, err.Error())
	}
}

func mapContinueError(tid string, err error) (*pb.ContinueAuthSessionResponse, error) {
	switch {
	case errors.Is(err, identity.ErrOIDCManualAccountLinkingRequired):
		return authFailureResponse(
			tid,
			"This email is already registered without this OIDC provider. Manual account linking is required.",
			ErrCodeOIDCManualLinkRequired,
		), nil
	case errors.Is(err, identity.ErrPasskeyNotLinked):
		return authFailureResponse(tid,
			"No user account is linked to this passkey credential.",
			ErrCodePasskeyNotLinked,
		), nil
	case errors.Is(err, identity.ErrLinkUnauthorized):
		return authFailureResponse(
			tid,
			"A valid session is required for this operation.",
			ErrCodeLinkUnauthorized,
		), nil
	case errors.Is(err, identity.ErrEmailAlreadyInUse):
		return authFailureResponse(
			tid,
			"That email address is already in use.",
			ErrCodeEmailAlreadyInUse,
		), nil
	case errors.Is(err, identity.ErrPasskeyAlreadyRegistered):
		return authFailureResponse(
			tid,
			"This passkey is already registered.",
			ErrCodePasskeyAlreadyRegistered,
		), nil
	case errors.Is(err, identity.ErrAuthenticationFailed):
		return authFailureResponse(tid, err.Error(), ErrCodeAuthenticationFailed), nil
	case errors.Is(err, identity.ErrInvalidInput):
		return authFailureResponse(tid, err.Error(), ErrCodeInvalidInput), nil
	case errors.Is(err, otp.ErrOTPSendRateLimited):
		return nil, status.Error(codes.ResourceExhausted, "OTP send rate limited; try again later")
	case errors.Is(err, identity.ErrSessionNotFound):
		return nil, status.Error(codes.NotFound, "transition not found")
	case errors.Is(err, identity.ErrInvalidSessionState):
		return authFailureResponse(tid, err.Error(), ErrCodeInvalidInput), nil
	default:
		if errors.Is(err, session.ErrSessionExpired) {
			return nil, status.Error(codes.FailedPrecondition, "transition expired")
		}
		return nil, err
	}
}

func authFailureResponse(tid, reason, code string) *pb.ContinueAuthSessionResponse {
	fail := &sessionpb.AuthFailure{}
	fail.SetReason(reason)
	fail.SetErrorCode(code)

	out := &pb.ContinueAuthSessionResponse{}
	out.SetTransitionId(tid)
	out.SetStatus(basic.AuthStatus_AUTH_STATE_FAILED)
	out.SetAuthFailure(fail)

	return out
}

// GetAuthorizedSession implements [authn.AuthnServiceServer].
func (g *GRPCHandler) GetAuthorizedSession(
	ctx context.Context,
	req *pb.GetSessionRequest,
) (*pb.GetSessionResponse, error) {
	wire := sessionTokenValue(req.GetSessionToken())
	if wire == "" {
		return nil, status.Error(codes.InvalidArgument, "missing session token")
	}

	res, err := g.accounts.Session.ResolveSessionToken(ctx, wire)
	if errors.Is(err, session.ErrSessionNotFound) || errors.Is(err, session.ErrSessionExpired) {
		out := &pb.GetSessionResponse{}
		out.SetValid(false)
		return out, nil
	}
	if err != nil {
		return nil, err
	}

	out := &pb.GetSessionResponse{}
	out.SetValid(true)
	out.SetSession(g.accounts.Session.AuthenticatedResultFromResolved(wire, res))

	return out, nil
}

// GetPublicKeys implements [authn.AuthnServiceServer].
func (g *GRPCHandler) GetPublicKeys(
	context.Context,
	*pb.GetPublicKeysRequest,
) (*pb.GetPublicKeysResponse, error) {
	panic("unimplemented")
}

// OIDCGrantConsent implements [authn.AuthnServiceServer].
func (g *GRPCHandler) OIDCGrantConsent(
	context.Context,
	*pb.OIDCGrantConsentRequest,
) (*pb.OIDCGrantConsentResponse, error) {
	panic("unimplemented")
}

// OIDCIntrospectToken implements [authn.AuthnServiceServer].
func (g *GRPCHandler) OIDCIntrospectToken(
	context.Context,
	*pb.OIDCIntrospectTokenRequest,
) (*pb.OIDCIntrospectTokenResponse, error) {
	panic("unimplemented")
}

// OIDCListGrantedConsents implements [authn.AuthnServiceServer].
func (g *GRPCHandler) OIDCListGrantedConsents(
	context.Context,
	*pb.OIDCListGrantedConsentsRequest,
) (*pb.OIDCListGrantedConsentsResponse, error) {
	panic("unimplemented")
}

// OIDCRevokeConsent implements [authn.AuthnServiceServer].
func (g *GRPCHandler) OIDCRevokeConsent(
	context.Context,
	*pb.OIDCRevokeConsentRequest,
) (*pb.OIDCRevokeConsentResponse, error) {
	panic("unimplemented")
}

// OIDCRevokeRefreshToken implements [authn.AuthnServiceServer].
func (g *GRPCHandler) OIDCRevokeRefreshToken(
	context.Context,
	*pb.OIDCRevokeRefreshTokenRequest,
) (*pb.OIDCRevokeRefreshTokenResponse, error) {
	panic("unimplemented")
}

// OIDCRotateAndGetAccessToken implements [authn.AuthnServiceServer].
func (g *GRPCHandler) OIDCRotateAndGetAccessToken(
	context.Context,
	*pb.OIDCRotateAndGetAccessTokenRequest,
) (*pb.OIDCRotateAndGetAccessTokenResponse, error) {
	panic("unimplemented")
}

// RevokeFederatedIdentity implements [authn.AuthnServiceServer].
func (g *GRPCHandler) RevokeFederatedIdentity(
	context.Context,
	*pb.RevokeFederatedIdentityRequest,
) (*pb.RevokeFederatedIdentityResponse, error) {
	panic("unimplemented")
}

// RevokeSession implements [authn.AuthnServiceServer].
func (g *GRPCHandler) RevokeSession(
	ctx context.Context,
	req *pb.RevokeSessionRequest,
) (*pb.RevokeSessionResponse, error) {
	wire := sessionTokenValue(req.GetSessionToken())
	if wire == "" {
		return nil, status.Error(codes.InvalidArgument, "missing session token")
	}

	err := g.accounts.Session.RevokeSessionToken(ctx, wire)
	if errors.Is(err, session.ErrSessionNotFound) {
		return nil, status.Error(codes.NotFound, "session not found")
	}
	if err != nil {
		return nil, err
	}

	out := &pb.RevokeSessionResponse{}
	out.SetSuccess(true)

	return out, nil
}

func protoIntent(i basic.AuthIntent) identity.AuthIntent {
	switch i {
	case basic.AuthIntent_AUTH_INTENT_LINK_ACCOUNT:
		return identity.IntentLinkAccount
	case basic.AuthIntent_AUTH_INTENT_REAUTHENTICATE:
		return identity.IntentReauthenticate
	case basic.AuthIntent_AUTH_INTENT_LOGIN:
		return identity.IntentLogin
	default:
		return identity.IntentLogin
	}
}

func sessionTokenValue(tok *sessionpb.SessionToken) string {
	if tok == nil {
		return ""
	}
	return strings.TrimSpace(tok.GetValue())
}
