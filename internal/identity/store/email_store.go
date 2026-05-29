package store

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"sanzi.io/muid/internal/authn/ent"
	"sanzi.io/muid/internal/authn/ent/useremail"
	"sanzi.io/muid/internal/authn/ent/useridentity"
	"sanzi.io/muid/pkg/enttx"
	"sanzi.io/muid/pkg/shared"
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

// LinkIdentity atomically creates the UserIdentity and the UserEmail sub-table row.
// is_primary is set to true only when the user has no existing active primary email.
func (s *EntEmailIdentityStore) LinkIdentity(
	ctx context.Context,
	userID uuid.UUID,
	claims IdentityClaims,
) (*Identity, error) {
	ec, ok := claims.(EmailIdentityClaims)
	if !ok {
		return nil, fmt.Errorf("store/email: expected EmailIdentityClaims, got %T", claims)
	}

	return enttx.Run(ctx, s.db.Tx, func(ctx context.Context, tx *ent.Tx) (*Identity, error) {
		identityRow, err := tx.UserIdentity.Create().
			SetUserID(userID).
			SetProvider("email").
			SetSubject(ec.Email).
			Save(ctx)
		if err != nil {
			return nil, err
		}

		// Set as primary only if the user has no existing active primary email.
		hasPrimary, err := tx.UserEmail.Query().
			Where(
				useremail.UserIDEQ(userID),
				useremail.IsPrimaryEQ(true),
				useremail.RevokedAtIsNil(),
			).
			Exist(ctx)
		if err != nil {
			return nil, err
		}

		err = tx.UserEmail.Create().
			SetID(shared.UUIDV7()).
			SetIdentityID(identityRow.ID).
			SetUserID(userID).
			SetEmail(ec.Email).
			SetIsPrimary(!hasPrimary).
			Exec(ctx)
		if err != nil {
			return nil, err
		}

		return identityFromRow(identityRow), nil
	})
}

// UpdateLastUsed is a no-op for email; updated_at is managed automatically.
func (s *EntEmailIdentityStore) UpdateLastUsed(ctx context.Context, identityID uuid.UUID) error {
	return nil
}

// RevokeIdentity marks the UserIdentity as revoked.
// The associated UserEmail row is append-only (revoked_at is immutable) and
// remains as a historical record; the unique email constraint prevents re-use.
func (s *EntEmailIdentityStore) RevokeIdentity(ctx context.Context, identityID uuid.UUID) error {
	return s.db.UserIdentity.UpdateOneID(identityID).
		SetRevokedAt(time.Now()).
		Exec(ctx)
}
