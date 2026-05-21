package authngrpc

import (
	"context"
	"errors"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "sanzi.io/muid/api/proto/authn/v1"
	sessionpb "sanzi.io/muid/api/proto/authn/v1/session"
	"sanzi.io/muid/internal/authn/account"
	authnflow "sanzi.io/muid/internal/authn/flow"
	"sanzi.io/muid/internal/identity"
	"sanzi.io/muid/internal/session"
	"sanzi.io/muid/internal/signature"
	grpcutils "sanzi.io/muid/pkg/grpc_utils"
	"sanzi.io/muid/pkg/log"
)

type GRPCHandler struct {
	pb.UnimplementedAuthnServiceServer

	flow     *authnflow.Service
	accounts *account.Accounts
	signing  signature.SignatureManager
}

type HandlerConfig struct {
	OTPSendCooldownSeconds int
	SignatureManager       signature.SignatureManager
}

func NewGRPCHandler(
	idm *identity.IdentityManager,
	transitionStore session.AuthTransitionStore,
	accounts *account.Accounts,
	config HandlerConfig,
) pb.AuthnServiceServer {
	return &GRPCHandler{
		flow: authnflow.NewService(authnflow.Dependencies{
			IdentityManager:        idm,
			TransitionStore:        transitionStore,
			Accounts:               accounts,
			OTPSendCooldownSeconds: config.OTPSendCooldownSeconds,
		}),
		accounts: accounts,
		signing:  config.SignatureManager,
	}
}

func (g *GRPCHandler) StartAuthSession(
	ctx context.Context,
	req *pb.StartAuthSessionRequest,
) (*pb.StartAuthSessionResponse, error) {
	return g.flow.StartAuthSession(ctx, req, optionalWireSession(ctx, req.GetSessionToken()))
}

func (g *GRPCHandler) ContinueAuthSession(
	ctx context.Context,
	req *pb.ContinueAuthSessionRequest,
) (*pb.ContinueAuthSessionResponse, error) {
	return g.flow.ContinueAuthSession(
		ctx,
		req,
		transitionIDString(ctx, req),
		optionalWireSession(ctx, req.GetSessionToken()),
	)
}

func (g *GRPCHandler) GetAuthorizedSession(
	ctx context.Context,
	req *pb.GetSessionRequest,
) (*pb.GetSessionResponse, error) {
	wire, err := requiredWireSession(ctx)
	if err != nil {
		return nil, err
	}

	res, err := g.accounts.Session.ResolveSessionToken(ctx, wire)
	if errors.Is(err, session.ErrSessionNotFound) || errors.Is(err, session.ErrSessionExpired) {
		out := &pb.GetSessionResponse{}
		out.SetValid(false)
		return out, nil
	}
	if err != nil {
		log.LogUnexpected(ctx, "authn get session", err.Error())
		return nil, grpcutils.GRPCInternalError()
	}

	out := &pb.GetSessionResponse{}
	out.SetValid(true)
	out.SetSession(g.accounts.Session.AuthenticatedResultFromResolved(wire, res))

	return out, nil
}

func (g *GRPCHandler) GetPublicKeys(
	ctx context.Context,
	_ *pb.GetPublicKeysRequest,
) (*pb.GetPublicKeysResponse, error) {
	if g.signing == nil {
		return nil, status.Error(codes.Unavailable, "signature manager unavailable")
	}

	keys, err := g.signing.PublicKeys(ctx)
	if err != nil {
		log.LogUnexpected(ctx, "authn public keys", err.Error())
		return nil, grpcutils.GRPCInternalError()
	}

	out := &pb.GetPublicKeysResponse{}
	out.SetPublicKeys(keys)
	return out, nil
}

func (g *GRPCHandler) OIDCGrantConsent(
	context.Context,
	*pb.OIDCGrantConsentRequest,
) (*pb.OIDCGrantConsentResponse, error) {
	return nil, status.Error(codes.Unimplemented, "method OIDCGrantConsent not implemented")
}

func (g *GRPCHandler) OIDCIntrospectToken(
	context.Context,
	*pb.OIDCIntrospectTokenRequest,
) (*pb.OIDCIntrospectTokenResponse, error) {
	return nil, status.Error(codes.Unimplemented, "method OIDCIntrospectToken not implemented")
}

func (g *GRPCHandler) OIDCListGrantedConsents(
	context.Context,
	*pb.OIDCListGrantedConsentsRequest,
) (*pb.OIDCListGrantedConsentsResponse, error) {
	return nil, status.Error(codes.Unimplemented, "method OIDCListGrantedConsents not implemented")
}

func (g *GRPCHandler) OIDCRevokeConsent(
	context.Context,
	*pb.OIDCRevokeConsentRequest,
) (*pb.OIDCRevokeConsentResponse, error) {
	return nil, status.Error(codes.Unimplemented, "method OIDCRevokeConsent not implemented")
}

func (g *GRPCHandler) OIDCRevokeRefreshToken(
	context.Context,
	*pb.OIDCRevokeRefreshTokenRequest,
) (*pb.OIDCRevokeRefreshTokenResponse, error) {
	return nil, status.Error(codes.Unimplemented, "method OIDCRevokeRefreshToken not implemented")
}

func (g *GRPCHandler) OIDCRotateAndGetAccessToken(
	context.Context,
	*pb.OIDCRotateAndGetAccessTokenRequest,
) (*pb.OIDCRotateAndGetAccessTokenResponse, error) {
	return nil, status.Error(
		codes.Unimplemented,
		"method OIDCRotateAndGetAccessToken not implemented",
	)
}

func (g *GRPCHandler) RevokeFederatedIdentity(
	context.Context,
	*pb.RevokeFederatedIdentityRequest,
) (*pb.RevokeFederatedIdentityResponse, error) {
	return nil, status.Error(codes.Unimplemented, "method RevokeFederatedIdentity not implemented")
}

func (g *GRPCHandler) RevokeSession(
	ctx context.Context,
	req *pb.RevokeSessionRequest,
) (*pb.RevokeSessionResponse, error) {
	wire, err := requiredWireSession(ctx)
	if err != nil {
		return nil, err
	}

	err = g.accounts.Session.RevokeSessionToken(ctx, wire)
	if errors.Is(err, session.ErrSessionNotFound) {
		return nil, status.Error(codes.NotFound, "session not found")
	}
	if err != nil {
		log.LogUnexpected(ctx, "authn revoke session", err.Error())
		return nil, grpcutils.GRPCInternalError()
	}

	out := &pb.RevokeSessionResponse{}
	out.SetSuccess(true)

	return out, nil
}

func sessionTokenValue(tok *sessionpb.SessionToken) string {
	if tok == nil {
		return ""
	}
	return strings.TrimSpace(tok.GetValue())
}
