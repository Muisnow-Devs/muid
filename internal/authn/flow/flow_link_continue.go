package flow

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"
	"sanzi.io/muid/internal/identity"
	"sanzi.io/muid/internal/session"
	grpcutils "sanzi.io/muid/pkg/grpc_utils"
	"sanzi.io/muid/pkg/log"
)

func (s *Service) validateLinkContinueSession(
	ctx context.Context,
	sess session.AuthSession,
	linkSessionToken string,
) error {
	intent, linkUserID, ok := sess.Store.AuthContext()
	if !ok || intent != string(identity.IntentLinkAccount) {
		return nil
	}
	return s.validateLinkContinueWire(ctx, linkUserID, linkSessionToken)
}

func (s *Service) validateLinkContinueWire(
	ctx context.Context,
	linkUserID, linkSessionToken string,
) error {
	linkUID, err := uuid.Parse(strings.TrimSpace(linkUserID))
	if err != nil {
		return identity.ErrInvalidSessionState
	}

	wire := strings.TrimSpace(linkSessionToken)
	if wire == "" {
		return identity.ErrLinkUnauthorized
	}

	res, err := s.sessions.ResolveSessionToken(ctx, wire)
	if errors.Is(err, session.ErrSessionNotFound) || errors.Is(err, session.ErrSessionExpired) {
		return identity.ErrLinkUnauthorized
	}
	if err != nil {
		log.LogUnexpected(ctx, "authn link continue resolve session", err.Error())
		return grpcutils.GRPCInternalError()
	}
	if res.UserID != linkUID {
		return identity.ErrLinkUnauthorized
	}

	return nil
}
