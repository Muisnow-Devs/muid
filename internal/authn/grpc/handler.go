package authngrpc

import (
	"context"
	"errors"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "sanzi.io/muid/api/proto/authn/v1"
	sessionpb "sanzi.io/muid/api/proto/authn/v1/session"
	"sanzi.io/muid/internal/authn/account"
	authnflow "sanzi.io/muid/internal/authn/flow"
	"sanzi.io/muid/internal/identity"
	"sanzi.io/muid/internal/session"
	grpcutils "sanzi.io/muid/pkg/grpc_utils"
	"sanzi.io/muid/pkg/log"
)

type GRPCHandler struct {
	pb.UnimplementedAuthnServiceServer

	flow     *authnflow.Service
	accounts *account.Accounts
}

type HandlerConfig struct {
	OTPSendCooldownSeconds int
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
	req *pb.GetAuthorizedSessionRequest,
) (*pb.GetAuthorizedSessionResponse, error) {
	wire, err := requiredWireSession(ctx)
	if err != nil {
		return nil, err
	}

	res, err := g.accounts.Session.ResolveSessionToken(ctx, wire)
	if errors.Is(err, session.ErrSessionNotFound) || errors.Is(err, session.ErrSessionExpired) {
		out := &pb.GetAuthorizedSessionResponse{}
		out.SetValid(false)
		return out, nil
	}
	if err != nil {
		log.LogUnexpected(ctx, "authn get session", err.Error())
		return nil, grpcutils.GRPCInternalError()
	}

	out := &pb.GetAuthorizedSessionResponse{}
	out.SetValid(true)
	out.SetSession(g.accounts.Session.AuthenticatedResultFromResolved(wire, res))

	return out, nil
}

func (g *GRPCHandler) GetAuthenticatedPrincipal(
	ctx context.Context,
	_ *pb.GetAuthenticatedPrincipalRequest,
) (*pb.GetAuthenticatedPrincipalResponse, error) {
	wire, err := requiredWireSession(ctx)
	if err != nil {
		return nil, err
	}

	res, err := g.accounts.Session.ResolveSessionToken(ctx, wire)
	if errors.Is(err, session.ErrSessionNotFound) || errors.Is(err, session.ErrSessionExpired) {
		out := &pb.GetAuthenticatedPrincipalResponse{}
		out.SetValid(false)
		return out, nil
	}
	if err != nil {
		log.LogUnexpected(ctx, "authn get principal", err.Error())
		return nil, grpcutils.GRPCInternalError()
	}

	out := &pb.GetAuthenticatedPrincipalResponse{}
	out.SetValid(true)
	out.SetPrincipal(g.accounts.Session.AuthenticatedPrincipalFromResolved(res))

	return out, nil
}

// RevokeFederatedIdentity unlinks a federated provider for the authenticated user.
// When the session was issued more than five minutes ago, clients receive FailedPrecondition
// with message "reauthentication required" and should complete StartAuthSession with
// AUTH_INTENT_REAUTHENTICATE (passing the current session_token), then retry with the
// newly issued session from AuthSuccess.
func (g *GRPCHandler) RevokeFederatedIdentity(
	ctx context.Context,
	req *pb.RevokeFederatedIdentityRequest,
) (*pb.RevokeFederatedIdentityResponse, error) {
	wire, err := requiredWireSession(ctx)
	if err != nil {
		return nil, err
	}

	provider := strings.TrimSpace(req.GetProvider())
	if provider == "" {
		return nil, status.Error(codes.InvalidArgument, "provider is required")
	}

	res, err := g.accounts.Session.ResolveSessionToken(ctx, wire)
	if errors.Is(err, session.ErrSessionNotFound) {
		return nil, status.Error(codes.NotFound, "session not found")
	}
	if errors.Is(err, session.ErrSessionExpired) {
		return nil, status.Error(codes.FailedPrecondition, "session expired")
	}
	if err != nil {
		log.LogUnexpected(ctx, "authn revoke federated resolve session", err.Error())
		return nil, grpcutils.GRPCInternalError()
	}

	issuedAt, err := g.accounts.Session.SessionCreatedAt(ctx, res.SessionID)
	if errors.Is(err, session.ErrSessionNotFound) {
		return nil, status.Error(codes.NotFound, "session not found")
	}
	if err != nil {
		log.LogUnexpected(ctx, "authn revoke federated session created_at", err.Error())
		return nil, grpcutils.GRPCInternalError()
	}

	if account.SessionRequiresReauthentication(issuedAt, time.Now()) {
		return nil, status.Error(
			codes.FailedPrecondition,
			account.ErrReauthenticationRequired.Error(),
		)
	}

	err = g.accounts.Federated.RevokeFederatedIdentity(ctx, res.UserID, provider)
	if errors.Is(err, account.ErrFederatedIdentityNotFound) {
		return nil, status.Error(codes.NotFound, "federated identity not found")
	}
	if err != nil {
		log.LogUnexpected(ctx, "authn revoke federated identity", err.Error())
		return nil, grpcutils.GRPCInternalError()
	}

	out := &pb.RevokeFederatedIdentityResponse{}
	out.SetSuccess(true)
	return out, nil
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
