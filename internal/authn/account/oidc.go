package account

import (
	"context"

	"github.com/google/uuid"
	claimspb "sanzi.io/muid/api/proto/shared/v1/claims"
	"sanzi.io/muid/internal/authn/ent"
	"sanzi.io/muid/internal/authn/ent/userfederatedidentity"
	"sanzi.io/muid/internal/identity"
)

type oidcService struct {
	store *Store
}

// LookupOIDCFederatedUser returns the user id when provider+subject is actively linked.
func (o *oidcService) LookupOIDCFederatedUser(
	ctx context.Context,
	providerName, subject string,
) (uuid.UUID, bool, error) {
	fed, err := o.store.DB.UserFederatedIdentity.Query().
		Where(
			userfederatedidentity.ProviderEQ(providerName),
			userfederatedidentity.SubjectEQ(subject),
			userfederatedidentity.RevokedAtIsNil(),
		).
		Only(ctx)
	if err == nil {
		return fed.UserID, true, nil
	}
	if ent.IsNotFound(err) {
		return uuid.Nil, false, nil
	}
	return uuid.Nil, false, err
}

// LookupOIDCLogin resolves an OIDC subject to an existing user or register-required data.
func (o *oidcService) LookupOIDCLogin(
	ctx context.Context,
	providerName, subject, email string,
	emailVerified bool,
	displayName, picture string,
) (uuid.UUID, *identity.RegisterRequired, error) {
	userID, found, err := o.LookupOIDCFederatedUser(ctx, providerName, subject)
	if err != nil {
		return uuid.Nil, nil, err
	}
	if found {
		return userID, nil, nil
	}

	if email == "" {
		return uuid.Nil, nil, errOIDCEmailRequired
	}

	reg, err := o.registerRequiredFromOIDCClaims(
		providerName,
		subject,
		email,
		emailVerified,
		displayName,
		picture,
	)
	if err != nil {
		return uuid.Nil, nil, err
	}
	return uuid.Nil, reg, nil
}

func (*oidcService) registerRequiredFromOIDCClaims(
	providerName, subject, email string,
	emailVerified bool,
	displayName, picture string,
) (*identity.RegisterRequired, error) {
	claims := &claimspb.IdentityInformation{}
	claims.SetEmail(email)
	claims.SetEmailVerified(emailVerified)
	claims.SetFederatedProvider(providerName)
	claims.SetFederatedSubject(subject)
	if displayName != "" {
		claims.SetName(displayName)
	}
	if picture != "" {
		claims.SetPicture(picture)
	}
	return &identity.RegisterRequired{Identity: claims}, nil
}
