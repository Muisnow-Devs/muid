package identity

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"
	"sanzi.io/muid/internal/authn/ent"
	"sanzi.io/muid/internal/authn/ent/userfederatedidentity"
	idn "sanzi.io/muid/internal/identity"
	"sanzi.io/muid/internal/session"
	"sanzi.io/muid/pkg/utils"
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

	transitionStore.Delete(ctx, transitionID)

	return idn.StepResult{
		Type: idn.StepAuthenticated,
		Authenticated: &idn.AuthenticatedIdentity{
			UserID: provisioned.String(),
		},
	}, nil
}

// ensureFederatedLink creates or verifies a UserFederatedIdentity for register finish.
func ensureFederatedLink(
	ctx context.Context,
	db *ent.Client,
	provider, subject string,
	provisioned uuid.UUID,
	claims session.RegisterPendingClaims,
) (uuid.UUID, error) {
	fed, err := db.UserFederatedIdentity.Query().
		Where(
			userfederatedidentity.ProviderEQ(provider),
			userfederatedidentity.SubjectEQ(subject),
		).
		Only(ctx)
	if err == nil {
		if fed.UserID != provisioned {
			return uuid.Nil, errors.Join(
				idn.ErrInvalidSessionState,
				errors.New("federated user mismatch"),
			)
		}
		return fed.UserID, nil
	}
	if !ent.IsNotFound(err) {
		return uuid.Nil, err
	}

	email := strings.TrimSpace(strings.ToLower(claims.Email))
	b := db.UserFederatedIdentity.Create().
		SetUserID(provisioned).
		SetProvider(provider).
		SetSubject(subject).
		SetEmail(email).
		SetEmailVerified(claims.EmailVerified)

	utils.FuncIfExists(&claims.Name, func(name string) { b = b.SetDisplayName(name) })
	utils.FuncIfExists(&claims.Picture, func(pic string) { b = b.SetNillableAvatarURL(&pic) })

	err = b.Exec(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	return provisioned, nil
}
