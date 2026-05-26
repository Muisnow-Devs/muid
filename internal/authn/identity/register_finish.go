package identity

import (
	"context"
	"errors"

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

	transitionStore.Delete(ctx, transitionID)

	return authenticatedStep(provisioned.String(), sess.Store), nil
}

// ensureFederatedLink creates or reactivates a UserFederatedIdentity for register finish.
func ensureFederatedLink(
	ctx context.Context,
	accounts *account.Accounts,
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

	err := accounts.Federated.LinkFederatedIdentity(ctx, params)
	if errors.Is(err, account.ErrFederatedSubjectLinkedToOtherUser) {
		return uuid.Nil, errors.Join(
			idn.ErrInvalidSessionState,
			errors.New("federated user mismatch"),
		)
	}
	if err != nil {
		return uuid.Nil, err
	}
	return provisioned, nil
}
