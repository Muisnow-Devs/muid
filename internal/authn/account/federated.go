package account

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
	"sanzi.io/muid/internal/authn/ent"
	"sanzi.io/muid/internal/authn/ent/userfederatedidentity"
	"sanzi.io/muid/pkg/utils"
)

type federatedService struct {
	store *Store
}

// FederatedLinkParams describes a federated identity to link or reactivate for a user.
type FederatedLinkParams struct {
	UserID        uuid.UUID
	Provider      string
	Subject       string
	Email         string
	EmailVerified bool
	DisplayName   string
	AvatarURL     *string
}

func normalizeFederatedProvider(provider string) string {
	return strings.ToLower(strings.TrimSpace(provider))
}

func normalizeFederatedSubject(subject string) string {
	return strings.TrimSpace(subject)
}

// LinkFederatedIdentity creates or reactivates a federated link for the given user.
// An active link for the same provider+subject on another user returns
// [ErrFederatedSubjectLinkedToOtherUser]. Reactivating a revoked row for the same user
// clears revoked_at and updates profile metadata.
func (f *federatedService) LinkFederatedIdentity(
	ctx context.Context,
	p FederatedLinkParams,
) error {
	provider := normalizeFederatedProvider(p.Provider)
	subject := normalizeFederatedSubject(p.Subject)
	if provider == "" || subject == "" {
		return ErrFederatedIdentityNotFound
	}

	fed, err := f.store.DB.UserFederatedIdentity.Query().
		Where(
			userfederatedidentity.ProviderEQ(provider),
			userfederatedidentity.SubjectEQ(subject),
		).
		Only(ctx)
	if err == nil {
		if fed.UserID != p.UserID {
			return ErrFederatedSubjectLinkedToOtherUser
		}
		if !fed.RevokedAt.IsZero() {
			return f.reactivateFederated(ctx, fed.ID, p)
		}
		return f.updateFederatedMetadata(ctx, fed.ID, p)
	}
	if !ent.IsNotFound(err) {
		return err
	}

	email := strings.TrimSpace(strings.ToLower(p.Email))
	b := f.store.DB.UserFederatedIdentity.Create().
		SetUserID(p.UserID).
		SetProvider(provider).
		SetSubject(subject).
		SetEmail(email).
		SetEmailVerified(p.EmailVerified)

	utils.FuncIfExists(&p.DisplayName, func(name string) { b = b.SetDisplayName(name) })
	utils.FuncIfExists(p.AvatarURL, func(url string) { b = b.SetNillableAvatarURL(&url) })

	return b.Exec(ctx)
}

func (f *federatedService) reactivateFederated(
	ctx context.Context,
	rowID uuid.UUID,
	p FederatedLinkParams,
) error {
	now := time.Now()
	u := f.store.DB.UserFederatedIdentity.UpdateOneID(rowID).
		ClearRevokedAt().
		SetUpdatedAt(now)

	email := strings.TrimSpace(strings.ToLower(p.Email))
	if email != "" {
		u = u.SetEmail(email).SetEmailVerified(p.EmailVerified)
	}
	utils.FuncIfExists(&p.DisplayName, func(name string) { u = u.SetDisplayName(name) })
	utils.FuncIfExists(p.AvatarURL, func(url string) { u = u.SetNillableAvatarURL(&url) })

	_, err := u.Save(ctx)
	return err
}

func (f *federatedService) updateFederatedMetadata(
	ctx context.Context,
	rowID uuid.UUID,
	p FederatedLinkParams,
) error {
	email := strings.TrimSpace(strings.ToLower(p.Email))
	if email == "" && p.DisplayName == "" && p.AvatarURL == nil {
		return nil
	}

	u := f.store.DB.UserFederatedIdentity.UpdateOneID(rowID)
	if email != "" {
		u = u.SetEmail(email).SetEmailVerified(p.EmailVerified)
	}
	utils.FuncIfExists(&p.DisplayName, func(name string) { u = u.SetDisplayName(name) })
	utils.FuncIfExists(p.AvatarURL, func(url string) { u = u.SetNillableAvatarURL(&url) })

	_, err := u.Save(ctx)
	return err
}

// RevokeFederatedIdentity soft-revokes the user's linked provider by setting revoked_at.
func (f *federatedService) RevokeFederatedIdentity(
	ctx context.Context,
	userID uuid.UUID,
	provider string,
) error {
	provider = normalizeFederatedProvider(provider)
	if provider == "" {
		return ErrFederatedIdentityNotFound
	}

	now := time.Now()
	n, err := f.store.DB.UserFederatedIdentity.Update().
		Where(
			userfederatedidentity.UserIDEQ(userID),
			userfederatedidentity.ProviderEQ(provider),
			userfederatedidentity.RevokedAtIsNil(),
		).
		SetRevokedAt(now).
		Save(ctx)
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrFederatedIdentityNotFound
	}
	return nil
}
