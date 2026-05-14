package account

import (
	"context"
	"errors"

	"github.com/google/uuid"
	claimspb "sanzi.io/muid/api/proto/shared/v1/claims"
	"sanzi.io/muid/internal/authn/ent"
	"sanzi.io/muid/internal/authn/ent/userfederatedidentity"
	"sanzi.io/muid/internal/authn/ent/userref"
	"sanzi.io/muid/internal/identity"
)

// ResolveOIDCLogin resolves or provisions a user for an OIDC subject.
//
// When a [ent.UserFederatedIdentity] row exists, returns its user id.
// When absent, if a [ent.UserRef] already exists for the email, returns
// [identity.ErrOIDCManualAccountLinkingRequired] (manual linking is required).
// Otherwise creates profile, UserRef, and UserFederatedIdentity.
func (s *Services) ResolveOIDCLogin(
	ctx context.Context,
	providerName, subject, email string,
	emailVerified bool,
	displayName, picture string,
) (uuid.UUID, error) {
	fed, err := s.DB.UserFederatedIdentity.Query().
		Where(
			userfederatedidentity.ProviderEQ(providerName),
			userfederatedidentity.SubjectEQ(subject),
		).
		Only(ctx)
	if err == nil {
		return fed.UserID, nil
	}
	if !ent.IsNotFound(err) {
		return uuid.Nil, err
	}

	if email == "" {
		return uuid.Nil, errors.New("authn: OIDC identity token has no email; cannot register")
	}

	_, err = s.DB.UserRef.Query().Where(userref.EmailEQ(email)).Only(ctx)
	if err == nil {
		return uuid.Nil, identity.ErrOIDCManualAccountLinkingRequired
	}
	if !ent.IsNotFound(err) {
		return uuid.Nil, err
	}

	claims := &claimspb.IdentityInformation{}
	claims.SetEmail(email)
	claims.SetEmailVerified(emailVerified)
	if displayName != "" {
		claims.SetName(displayName)
	}
	if picture != "" {
		claims.SetPicture(picture)
	}

	uid, err := s.provisionFromProfile(ctx, email, claims)
	if err != nil {
		return uuid.Nil, err
	}

	b := s.DB.UserFederatedIdentity.Create().
		SetUserID(uid).
		SetProvider(providerName).
		SetSubject(subject).
		SetEmail(email).
		SetEmailVerified(emailVerified)
	if displayName != "" {
		b = b.SetDisplayName(displayName)
	}
	if picture != "" {
		b = b.SetNillableAvatarURL(&picture)
	}
	if err := b.Exec(ctx); err != nil {
		return uuid.Nil, err
	}
	return uid, nil
}
