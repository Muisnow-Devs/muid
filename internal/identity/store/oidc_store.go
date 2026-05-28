package store

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"sanzi.io/muid/internal/authn/ent"
	"sanzi.io/muid/internal/authn/ent/useridentity"
	"sanzi.io/muid/pkg/enttx"
)

// EntOIDCIdentityStore is the Ent-backed IdentityStore for all OIDC/OAuth methods.
// A single instance serves every configured OIDC provider; the provider name is
// carried by OIDCIdentityClaims and the provider+subject query arguments.
type EntOIDCIdentityStore struct {
	db *ent.Client
}

func NewEntOIDCIdentityStore(db *ent.Client) IdentityStore {
	return &EntOIDCIdentityStore{db: db}
}

// FindUser returns the active UserIdentity for the given provider+subject pair.
func (s *EntOIDCIdentityStore) FindUser(
	ctx context.Context,
	provider, subject string,
) (*Identity, error) {
	row, err := s.db.UserIdentity.Query().
		Where(
			useridentity.ProviderEQ(provider),
			useridentity.SubjectEQ(subject),
			useridentity.RevokedAtIsNil(),
		).
		Only(ctx)
	if ent.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return identityFromRow(row), nil
}

// LinkIdentity atomically creates UserIdentity + UserFederatedIdentity.
func (s *EntOIDCIdentityStore) LinkIdentity(
	ctx context.Context,
	userID uuid.UUID,
	claims IdentityClaims,
) (*Identity, error) {
	oc, ok := claims.(OIDCIdentityClaims)
	if !ok {
		return nil, fmt.Errorf("store/oidc: expected OIDCIdentityClaims, got %T", claims)
	}

	return enttx.Run(ctx, s.db.Tx, func(ctx context.Context, tx *ent.Tx) (*Identity, error) {
		identityRow, err := tx.UserIdentity.Create().
			SetUserID(userID).
			SetProvider(oc.Provider).
			SetSubject(oc.Subject).
			Save(ctx)
		if err != nil {
			return nil, err
		}

		fedCreate := tx.UserFederatedIdentity.Create().
			SetIdentityID(identityRow.ID).
			SetProvider(oc.Provider).
			SetSubject(oc.Subject).
			SetEmailVerified(oc.EmailVerified)

		if oc.Email != "" {
			fedCreate = fedCreate.SetEmail(oc.Email)
		}
		if oc.DisplayName != "" {
			fedCreate = fedCreate.SetDisplayName(oc.DisplayName)
		}
		if oc.AvatarURL != "" {
			fedCreate = fedCreate.SetAvatarURL(oc.AvatarURL)
		}

		if err = fedCreate.Exec(ctx); err != nil {
			return nil, err
		}

		return identityFromRow(identityRow), nil
	})
}

// UpdateLastUsed is a no-op for OIDC; updated_at is managed automatically.
func (s *EntOIDCIdentityStore) UpdateLastUsed(ctx context.Context, identityID uuid.UUID) error {
	return nil
}

// RevokeIdentity marks the UserIdentity as revoked.
func (s *EntOIDCIdentityStore) RevokeIdentity(ctx context.Context, identityID uuid.UUID) error {
	return s.db.UserIdentity.UpdateOneID(identityID).
		SetRevokedAt(time.Now()).
		Exec(ctx)
}
