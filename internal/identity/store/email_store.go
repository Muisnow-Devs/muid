package store

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"sanzi.io/muid/internal/authn/ent"
	"sanzi.io/muid/internal/authn/ent/useridentity"
)

// EntEmailIdentityStore is the Ent-backed IdentityStore for the email/OTP method.
type EntEmailIdentityStore struct {
	db *ent.Client
}

func NewEntEmailIdentityStore(db *ent.Client) IdentityStore {
	return &EntEmailIdentityStore{db: db}
}

// FindUser returns the active UserIdentity for provider="email", subject=email.
func (s *EntEmailIdentityStore) FindUser(
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

// LinkIdentity creates a UserIdentity row for the email method.
// Email has no method-specific sub-table.
func (s *EntEmailIdentityStore) LinkIdentity(
	ctx context.Context,
	userID uuid.UUID,
	claims IdentityClaims,
) (*Identity, error) {
	ec, ok := claims.(EmailIdentityClaims)
	if !ok {
		return nil, fmt.Errorf("store/email: expected EmailIdentityClaims, got %T", claims)
	}

	row, err := s.db.UserIdentity.Create().
		SetUserID(userID).
		SetProvider("email").
		SetSubject(ec.Email).
		Save(ctx)
	if err != nil {
		return nil, err
	}
	return identityFromRow(row), nil
}

// UpdateLastUsed is a no-op for email; updated_at is managed automatically.
func (s *EntEmailIdentityStore) UpdateLastUsed(ctx context.Context, identityID uuid.UUID) error {
	return nil
}

// RevokeIdentity marks the UserIdentity as revoked.
func (s *EntEmailIdentityStore) RevokeIdentity(ctx context.Context, identityID uuid.UUID) error {
	return s.db.UserIdentity.UpdateOneID(identityID).
		SetRevokedAt(time.Now()).
		Exec(ctx)
}
