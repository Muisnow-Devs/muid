package flow

import (
	"context"
	"strings"

	"github.com/google/uuid"
	"sanzi.io/muid/internal/identity"
	"sanzi.io/muid/internal/session"
	grpcutils "sanzi.io/muid/pkg/grpc_utils"
	"sanzi.io/muid/pkg/log"
)

func (s *Service) resolveRegisterRequired(
	ctx context.Context,
	_ string,
	sess session.AuthSession,
	reg *identity.RegisterRequired,
	linkSessionToken string,
) (uuid.UUID, bool, error) {
	if reg == nil || reg.Identity == nil {
		log.LogUnexpected(ctx, "authn resolve register required", "missing register-required data")
		return uuid.Nil, false, grpcutils.GRPCInternalError()
	}

	intent, _, _ := sess.Store.AuthContext()
	if strings.TrimSpace(reg.Identity.GetFederatedProvider()) == "" {
		uid, err := s.provision.ProvisionUser(ctx, reg)
		return uid, false, err
	}

	switch intent {
	case string(identity.IntentLinkAccount):
		uid, err := s.resolveOIDCLinkRegister(ctx, sess.Store, linkSessionToken)
		return uid, false, err
	default:
		return s.resolveOIDCLoginRegister(ctx, reg)
	}
}

func (s *Service) resolveOIDCLoginRegister(
	ctx context.Context,
	reg *identity.RegisterRequired,
) (uuid.UUID, bool, error) {
	email := strings.TrimSpace(strings.ToLower(reg.Identity.GetEmail()))
	if email == "" {
		return uuid.Nil, false, identity.ErrInvalidInput
	}

	existing, found, err := s.email.LookupUserByEmail(ctx, email)
	if err != nil {
		log.LogUnexpected(ctx, "authn oidc login email lookup", err.Error())
		return uuid.Nil, false, grpcutils.GRPCInternalError()
	}
	if found {
		return existing, true, nil
	}

	uid, err := s.provision.ProvisionUser(ctx, reg)
	return uid, false, err
}

func (s *Service) resolveOIDCLinkRegister(
	ctx context.Context,
	store session.SessionStore,
	linkSessionToken string,
) (uuid.UUID, error) {
	_, linkUserID, ok := store.AuthContext()
	if !ok {
		return uuid.Nil, identity.ErrInvalidSessionState
	}

	err := s.validateLinkContinueWire(ctx, linkUserID, linkSessionToken)
	if err != nil {
		return uuid.Nil, err
	}

	linkUID, err := uuid.Parse(strings.TrimSpace(linkUserID))
	if err != nil {
		return uuid.Nil, identity.ErrInvalidSessionState
	}

	return linkUID, nil
}

func (s *Service) cleanTransition(ctx context.Context, transitionID string) {
	err := s.transitionStore.Delete(ctx, transitionID)
	if err != nil {
		log.LogUnexpected(ctx, "authn clean transition", err.Error())
	}
}
