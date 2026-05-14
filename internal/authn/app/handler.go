package app

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "sanzi.io/muid/api/proto/authn/v1"
	"sanzi.io/muid/api/proto/authn/v1/basic"
	"sanzi.io/muid/api/proto/authn/v1/challenge"
	proofpb "sanzi.io/muid/api/proto/authn/v1/proof"
	sessionpb "sanzi.io/muid/api/proto/authn/v1/session"
	implIdentity "sanzi.io/muid/internal/authn/infra/identity"
	"sanzi.io/muid/internal/identity"
	"sanzi.io/muid/internal/otp"
	"sanzi.io/muid/internal/session"
)

type GRPCHandler struct {
	pb.UnimplementedAuthnServiceServer

	optStore        otp.OTPStore
	idm             *identity.IdentityManager
	transitionStore session.AuthTransitionStore
}

func CreateGRPCHandler(infra *InfraDependencies) pb.AuthnServiceServer {
	return &GRPCHandler{
		optStore:        infra.OTPStore,
		idm:             infra.IdentityManager,
		transitionStore: infra.TransitionStore,
	}
}

func (g *GRPCHandler) StartAuthSession(
	ctx context.Context,
	req *pb.StartAuthSessionRequest,
) (*pb.StartAuthSessionResponse, error) {
	providerName, err := providerNameForMethod(req.GetMethod(), strings.TrimSpace(req.GetIdentifier()))
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	prov, err := g.idm.GetProvider(providerName)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	step, err := prov.Start(ctx, identity.StartInput{
		Provider:   providerName,
		Identifier: strings.TrimSpace(req.GetIdentifier()),
	})
	if err != nil {
		return nil, mapStartError(err)
	}

	sess, err := g.transitionStore.Get(ctx, step.TransitionId)
	if err != nil {
		return nil, status.Error(codes.Internal, "load transition after start")
	}

	ch, err := buildAuthChallenge(req.GetMethod(), sess, step)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &pb.StartAuthSessionResponse{
		TransitionId: step.TransitionId,
		Challenge:    ch,
	}, nil
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
		TransitionId: tid,
		Payload:      payload,
	})
	if err != nil {
		return mapContinueError(tid, err)
	}

	if step.Type != identity.StepComplete || step.AuthenticatedResult == nil {
		return nil, status.Error(codes.Internal, "provider did not complete authentication")
	}

	return &pb.ContinueAuthSessionResponse{
		TransitionId: tid,
		Status:       basic.AuthStatus_AUTH_STATE_AUTHENTICATED,
		Result: &pb.ContinueAuthSessionResponse_AuthSuccess{
			AuthSuccess: &sessionpb.AuthSuccess{
				Result: step.AuthenticatedResult,
			},
		},
	}, nil
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
) (*challenge.AuthChallenge, error) {
	now := time.Now()
	out := &challenge.AuthChallenge{
		ChallengeId: step.TransitionId,
		IssuedAt:    now.Unix(),
		ExpiresAt:   now.Add(15 * time.Minute).Unix(),
	}

	switch method {
	case basic.AuthMethod_AUTH_METHOD_EMAIL_OTP:
		if sess.Store.Email == nil {
			return nil, fmt.Errorf("missing email transition data")
		}
		out.Challenge = &challenge.AuthChallenge_EmailChallenge{
			EmailChallenge: &challenge.EmailChallenge{
				EmailMasked:          maskEmail(sess.Store.Email.Email),
				ResendCooldownMillis: 60_000,
			},
		}
	case basic.AuthMethod_AUTH_METHOD_OAUTH:
		out.Challenge = &challenge.AuthChallenge_OauthChallenge{
			OauthChallenge: &challenge.OAuthChallenge{
				Provider: sess.Provider,
				AuthUrl:  step.RedirectURL,
			},
		}
	case basic.AuthMethod_AUTH_METHOD_PASSKEY:
		out.Challenge = &challenge.AuthChallenge_PasskeyChallenge{
			PasskeyChallenge: &challenge.PasskeyChallenge{
				State:                                 step.TransitionId,
				PublicKeyCredentialRequestOptionsJson: step.PasskeyPublicKeyCredentialRequestOptionsJSON,
				TimeoutMillis:                         step.PasskeyTimeoutMillis,
			},
		}
	default:
		return nil, fmt.Errorf("unsupported method for challenge mapping")
	}
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
	switch x := proof.Proof.(type) {
	case *proofpb.AuthProof_EmailProof:
		return map[string]any{
			implIdentity.EmailPayloadKeyCode: x.EmailProof.GetOtpCode(),
		}, nil
	case *proofpb.AuthProof_OauthProof:
		return map[string]any{
			implIdentity.OIDCPayloadKeyCode:  x.OauthProof.GetCode(),
			implIdentity.OIDCPayloadKeyState: x.OauthProof.GetState(),
		}, nil
	case *proofpb.AuthProof_PasskeyProof:
		return map[string]any{
			"credential_assertion_response_json": x.PasskeyProof.GetCredentialAssertionResponseJson(),
		}, nil
	default:
		return nil, status.Error(codes.InvalidArgument, "unsupported proof type")
	}
}

func mapStartError(err error) error {
	if errors.Is(err, identity.ErrInvalidInput) {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	return status.Error(codes.Internal, err.Error())
}

func mapContinueError(tid string, err error) (*pb.ContinueAuthSessionResponse, error) {
	switch {
	case errors.Is(err, identity.ErrOIDCManualAccountLinkingRequired):
		return authFailureResponse(tid,
			"This email is already registered without this OIDC provider. Manual account linking is required.",
			ErrCodeOIDCManualLinkRequired,
		), nil
	case errors.Is(err, identity.ErrPasskeyNotLinked):
		return authFailureResponse(tid,
			"No user account is linked to this passkey credential.",
			ErrCodePasskeyNotLinked,
		), nil
	case errors.Is(err, identity.ErrAuthenticationFailed):
		return authFailureResponse(tid, err.Error(), ErrCodeAuthenticationFailed), nil
	case errors.Is(err, identity.ErrInvalidInput):
		return authFailureResponse(tid, err.Error(), ErrCodeInvalidInput), nil
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
	return &pb.ContinueAuthSessionResponse{
		TransitionId: tid,
		Status:       basic.AuthStatus_AUTH_STATE_FAILED,
		Result: &pb.ContinueAuthSessionResponse_AuthFailure{
			AuthFailure: &sessionpb.AuthFailure{
				Reason:    reason,
				ErrorCode: code,
			},
		},
	}
}

// GetAuthorizedSession implements [authn.AuthnServiceServer].
func (g *GRPCHandler) GetAuthorizedSession(
	context.Context,
	*pb.GetSessionRequest,
) (*pb.GetSessionResponse, error) {
	panic("unimplemented")
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
	context.Context,
	*pb.RevokeSessionRequest,
) (*pb.RevokeSessionResponse, error) {
	panic("unimplemented")
}
