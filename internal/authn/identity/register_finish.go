package identity

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"
	"sanzi.io/muid/internal/authn/account"
	idn "sanzi.io/muid/internal/identity"
	"sanzi.io/muid/internal/session"
)

func finishRegisterAfterLink(
	ctx context.Context,
	transitionStore session.AuthTransitionStore,
	transitionID string,
	linkedUserID uuid.UUID,
	provisioned uuid.UUID,
) (idn.StepResult, error) {
	if linkedUserID != provisioned {
		return idn.StepResult{}, errors.Join(
			idn.ErrInvalidSessionState,
			errors.New("provisioned user mismatch after link"),
		)
	}

	sess, err := transitionStore.Get(ctx, transitionID)
	if err != nil {
		return idn.StepResult{}, err
	}

	return authenticatedStep(provisioned.String(), sess.Store), nil
}

func validateOIDCFinishRegister(
	ctx context.Context,
	intent string,
	linkUserID string,
	provisioned uuid.UUID,
	pending session.RegisterPending,
	email account.Email,
) error {
	claims := pending.Claims
	emailNorm := strings.TrimSpace(strings.ToLower(claims.Email))
	if emailNorm == "" {
		return idn.ErrInvalidSessionState
	}

	switch intent {
	case string(idn.IntentLinkAccount):
		linkUID, err := uuid.Parse(strings.TrimSpace(linkUserID))
		if err != nil || provisioned != linkUID {
			return idn.ErrLinkUnauthorized
		}
		inUse, err := email.EmailUsedByOther(ctx, emailNorm, linkUID)
		if err != nil {
			return err
		}
		if inUse {
			return idn.ErrOIDCManualAccountLinkingRequired
		}
		return nil
	default:
		if pending.ResolvedExistingUser {
			return idn.ErrOIDCManualAccountLinkingRequired
		}
		owner, found, err := email.LookupUserByEmail(ctx, emailNorm)
		if err != nil {
			return err
		}
		if found && owner != provisioned {
			return idn.ErrOIDCManualAccountLinkingRequired
		}
		return nil
	}
}

func mapFederatedLinkError(err error, linkIntent bool) error {
	if errors.Is(err, account.ErrFederatedSubjectLinkedToOtherUser) {
		if linkIntent {
			return idn.ErrEmailAlreadyInUse
		}
		return idn.ErrOIDCManualAccountLinkingRequired
	}
	return err
}

// ensureFederatedLink creates or reactivates a UserFederatedIdentity for register finish.
func ensureFederatedLink(
	ctx context.Context,
	federated account.Federated,
	provider, subject string,
	provisioned uuid.UUID,
	claims session.RegisterPendingClaims,
) (uuid.UUID, error) {
	params := account.FederatedLinkParams{
		UserID:        provisioned,
		Provider:      provider,
		Subject:       subject,
		Email:         claims.Email,
		EmailVerified: claims.EmailVerified,
		DisplayName:   claims.Name,
	}
	if claims.Picture != "" {
		pic := claims.Picture
		params.AvatarURL = &pic
	}

	err := federated.LinkFederatedIdentity(ctx, params)
	if err != nil {
		return uuid.Nil, err
	}
	return provisioned, nil
}
