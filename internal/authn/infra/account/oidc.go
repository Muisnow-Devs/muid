package account

import (
	"context"

	"github.com/google/uuid"
	claimspb "sanzi.io/muid/api/proto/shared/v1/claims"
	"sanzi.io/muid/internal/authn/ent"
	"sanzi.io/muid/internal/authn/ent/userfederatedidentity"
	"sanzi.io/muid/internal/authn/ent/userref"
	"sanzi.io/muid/internal/identity"
)

type oidcService struct {
	store *Store
}

// LookupOIDCLogin resolves an OIDC subject to an existing user or register-required data.
func (o *oidcService) LookupOIDCLogin(
	ctx context.Context,
	providerName, subject, email string,
	emailVerified bool,
	displayName, picture string,
) (uuid.UUID, *identity.RegisterRequired, error) {
	fed, err := o.store.DB.UserFederatedIdentity.Query().
		Where(
			userfederatedidentity.ProviderEQ(providerName),
			userfederatedidentity.SubjectEQ(subject),
		).
		Only(ctx)
	if err == nil {
		return fed.UserID, nil, nil
	}
	if !ent.IsNotFound(err) {
		return uuid.Nil, nil, err
	}

	if email == "" {
		return uuid.Nil, nil, errOIDCEmailRequired
	}

	_, err = o.store.DB.UserRef.Query().Where(userref.EmailEQ(email)).Only(ctx)
	if err == nil {
		return uuid.Nil, nil, identity.ErrOIDCManualAccountLinkingRequired
	}
	if !ent.IsNotFound(err) {
		return uuid.Nil, nil, err
	}

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

	return uuid.Nil, &identity.RegisterRequired{Identity: claims}, nil
}
