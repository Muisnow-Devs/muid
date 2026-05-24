package flow

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
	"sanzi.io/muid/internal/authn/account"
	implIdentity "sanzi.io/muid/internal/authn/identity"
	"sanzi.io/muid/internal/identity"
	"sanzi.io/muid/internal/otp"
	"sanzi.io/muid/internal/session"
	grpcutils "sanzi.io/muid/pkg/grpc_utils"
	"sanzi.io/muid/pkg/localetime"
	"sanzi.io/muid/pkg/log"
)

type Service struct {
	idm                     *identity.IdentityManager
	transitionStore         session.AuthTransitionStore
	accounts                *account.Accounts
	otpResendCooldownMillis int64
}

type Dependencies struct {
	IdentityManager        *identity.IdentityManager
	TransitionStore        session.AuthTransitionStore
	Accounts               *account.Accounts
	OTPSendCooldownSeconds int
}

func NewService(deps Dependencies) *Service {
	cooldownSec := deps.OTPSendCooldownSeconds
	if cooldownSec < 0 {
		cooldownSec = 0
	}
	return &Service{
		idm:                     deps.IdentityManager,
		transitionStore:         deps.TransitionStore,
		accounts:                deps.Accounts,
		otpResendCooldownMillis: int64(cooldownSec) * 1000,
	}
}

func (s *Service) StartAuthSession(
	ctx context.Context,
	req *pb.StartAuthSessionRequest,
	linkSessionToken string,
) (*pb.StartAuthSessionResponse, error) {
	providerName, err := providerNameForMethod(
		req.GetMethod(),
		strings.TrimSpace(req.GetIdentifier()),
	)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	locale := strings.TrimSpace(req.GetLocale())
	timezone := strings.TrimSpace(req.GetTimezone())
	if timezone != "" && !localetime.ValidTimezone(timezone) {
		return nil, status.Error(codes.InvalidArgument, "timezone must be a valid IANA time zone")
	}

	prov, err := s.idm.GetProvider(providerName)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	step, err := prov.Start(ctx, identity.StartInput{
		Provider:         providerName,
		Identifier:       strings.TrimSpace(req.GetIdentifier()),
		Intent:           protoIntent(req.GetIntent()),
		LinkSessionToken: linkSessionToken,
		Locale:           locale,
		Timezone:         timezone,
	})
	if err != nil {
		return nil, mapStartError(ctx, err)
	}

	sess, err := s.transitionStore.Get(ctx, step.TransitionId)
	if err != nil {
		log.LogUnexpected(ctx, "authn start load transition", err.Error())
		return nil, grpcutils.GRPCInternalError()
	}

	ch, err := buildAuthChallenge(req.GetMethod(), sess, step, s.otpResendCooldownMillis)
	if err != nil {
		log.LogUnexpected(ctx, "authn start build challenge", err.Error())
		return nil, grpcutils.GRPCInternalError()
	}

	out := &pb.StartAuthSessionResponse{}
	out.SetTransitionId(step.TransitionId)
	out.SetChallenge(ch)
	return out, nil
}

func (s *Service) ContinueAuthSession(
	ctx context.Context,
	req *pb.ContinueAuthSessionRequest,
	transitionID string,
	linkSessionToken string,
) (*pb.ContinueAuthSessionResponse, error) {
	tid := strings.TrimSpace(transitionID)
	sess, err := s.transitionStore.Get(ctx, tid)
	if err != nil {
		return nil, mapTransitionLoadError(ctx, err)
	}

	prov, err := s.idm.GetProvider(sess.Provider)
	if err != nil {
		log.LogUnexpected(ctx, "authn continue provider lookup", err.Error())
		return nil, grpcutils.GRPCInternalError()
	}

	payload, err := proofToPayload(req.GetProof())
	if err != nil {
		return nil, err
	}

	step, err := prov.Continue(ctx, identity.ContinueInput{
		TransitionId:     tid,
		Payload:          payload,
		LinkSessionToken: linkSessionToken,
	})
	if err != nil {
		return mapContinueError(ctx, tid, err)
	}

	if step.Type == identity.StepInput {
		return s.continueAwaitingChallenge(ctx, tid, sess, step)
	}

	return s.finishAuthStep(ctx, req, sess, step, tid, linkSessionToken)
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
			switch pk.Ceremony {
			case implIdentity.PasskeyCeremonyRegistration:
				pc.SetCeremony(challenge.PasskeyCeremony_PASSKEY_CEREMONY_REGISTRATION)
				pc.SetPublicKeyCredentialCreationOptionsJson(
					pk.PublicKeyCredentialCreationOptionsJSON,
				)
			default:
				pc.SetCeremony(challenge.PasskeyCeremony_PASSKEY_CEREMONY_AUTHENTICATION)
				pc.SetPublicKeyCredentialRequestOptionsJson(
					pk.PublicKeyCredentialRequestOptionsJSON,
				)
			}
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

func (s *Service) continueAwaitingChallenge(
	ctx context.Context,
	tid string,
	sess session.AuthSession,
	step identity.StepResult,
) (*pb.ContinueAuthSessionResponse, error) {
	if strings.TrimSpace(step.TransitionId) != "" && step.TransitionId != tid {
		log.LogUnexpected(
			ctx,
			"authn continue transition mismatch",
			"transition mismatch after continue",
		)
		return nil, grpcutils.GRPCInternalError()
	}

	method, err := authMethodForProvider(sess.Provider)
	if err != nil {
		log.LogUnexpected(ctx, "authn continue method lookup", err.Error())
		return nil, grpcutils.GRPCInternalError()
	}

	ch, err := buildAuthChallenge(method, sess, step, s.otpResendCooldownMillis)
	if err != nil {
		log.LogUnexpected(ctx, "authn continue build challenge", err.Error())
		return nil, grpcutils.GRPCInternalError()
	}

	cr := &sessionpb.ChallengeRequired{}
	cr.SetChallenge(ch)

	out := &pb.ContinueAuthSessionResponse{}
	out.SetTransitionId(tid)
	out.SetStatus(basic.AuthStatus_AUTH_STATUS_CHALLENGE_REQUIRED)
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

func mapStartError(ctx context.Context, err error) error {
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
		log.LogUnexpected(ctx, "authn start provider", err.Error())
		return grpcutils.GRPCInternalError()
	}
}

func mapContinueError(
	ctx context.Context,
	tid string,
	err error,
) (*pb.ContinueAuthSessionResponse, error) {
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
	case errors.Is(err, session.ErrSessionExpired):
		return nil, status.Error(codes.FailedPrecondition, "transition expired")
	default:
		log.LogUnexpected(ctx, "authn continue provider", err.Error())
		return nil, grpcutils.GRPCInternalError()
	}
}

func mapTransitionLoadError(ctx context.Context, err error) error {
	switch {
	case errors.Is(err, session.ErrSessionNotFound):
		return status.Error(codes.NotFound, "transition not found")
	case errors.Is(err, session.ErrSessionExpired):
		return status.Error(codes.FailedPrecondition, "transition expired")
	default:
		log.LogUnexpected(ctx, "authn continue load transition", err.Error())
		return grpcutils.GRPCInternalError()
	}
}

func authFailureResponse(tid, reason, code string) *pb.ContinueAuthSessionResponse {
	fail := &sessionpb.AuthFailure{}
	fail.SetReason(reason)
	fail.SetErrorCode(code)

	out := &pb.ContinueAuthSessionResponse{}
	out.SetTransitionId(tid)
	out.SetStatus(basic.AuthStatus_AUTH_STATUS_FAILED)
	out.SetAuthFailure(fail)

	return out
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
