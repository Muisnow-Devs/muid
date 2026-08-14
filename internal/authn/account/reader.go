package account

import (
	"context"
	"fmt"

	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"

	authnent "sanzi.io/muid/internal/authn/ent"
	"sanzi.io/muid/internal/authn/ent/useremail"
	"sanzi.io/muid/internal/authn/ent/userfederatedidentity"
	"sanzi.io/muid/internal/authn/ent/useridentity"
	"sanzi.io/muid/internal/authn/ent/userref"
)

// Manager reads account state from Authn persistence.
type Manager struct {
	db *authnent.Client
}

// NewManager creates an account reader backed by the Authn Ent client.
func NewManager(db *authnent.Client) *Manager {
	return &Manager{db: db}
}

// GetMyAccount returns the current account snapshot for userID.
func (m *Manager) GetMyAccount(ctx context.Context, userID uuid.UUID) (Snapshot, error) {
	user, err := m.db.UserRef.Query().
		Where(userref.IDEQ(userID)).
		Select(userref.FieldStatus, userref.FieldCreatedAt).
		Only(ctx)
	if authnent.IsNotFound(err) {
		return Snapshot{}, ErrNotFound
	}
	if err != nil {
		return Snapshot{}, fmt.Errorf("query user ref: %w", err)
	}

	status, ok := accountStatus(user.Status)
	if !ok {
		return Snapshot{}, ErrInvalidState
	}

	emails, err := m.db.UserEmail.Query().
		Where(
			useremail.UserIDEQ(userID),
			useremail.IsPrimaryEQ(true),
			useremail.RevokedAtIsNil(),
			useremail.HasIdentityWith(
				useridentity.UserIDEQ(userID),
				useridentity.ProviderEQ("email"),
				useridentity.RevokedAtIsNil(),
			),
		).
		WithIdentity().
		Limit(2).
		All(ctx)
	if err != nil {
		return Snapshot{}, fmt.Errorf("query primary email: %w", err)
	}
	if len(emails) != 1 {
		return Snapshot{}, ErrInvalidState
	}
	primaryEmail := emails[0]
	primaryIdentity := primaryEmail.Edges.Identity
	if primaryIdentity == nil ||
		primaryIdentity.UserID != userID ||
		primaryIdentity.Provider != "email" ||
		primaryIdentity.Subject != primaryEmail.Email {
		return Snapshot{}, ErrInvalidState
	}

	federated, err := m.db.UserFederatedIdentity.Query().
		Where(
			userfederatedidentity.RevokedAtIsNil(),
			userfederatedidentity.HasIdentityWith(
				useridentity.UserIDEQ(userID),
				useridentity.RevokedAtIsNil(),
			),
		).
		WithIdentity().
		Order(
			userfederatedidentity.ByProvider(sql.OrderAsc()),
			userfederatedidentity.ByLinkedAt(sql.OrderAsc()),
			userfederatedidentity.ByID(sql.OrderAsc()),
		).
		All(ctx)
	if err != nil {
		return Snapshot{}, fmt.Errorf("query linked identities: %w", err)
	}

	linked := make([]LinkedIdentity, 0, len(federated))
	for _, identity := range federated {
		parent := identity.Edges.Identity
		if parent == nil || parent.Provider != identity.Provider {
			return Snapshot{}, ErrInvalidState
		}
		linked = append(linked, LinkedIdentity{
			Provider: identity.Provider,
			LinkedAt: identity.LinkedAt,
		})
	}

	return Snapshot{
		Status:           status,
		PrimaryEmail:     primaryEmail.Email,
		CreatedAt:        user.CreatedAt,
		LinkedIdentities: linked,
	}, nil
}

func accountStatus(status userref.Status) (Status, bool) {
	switch status {
	case userref.StatusActive:
		return StatusActive, true
	case userref.StatusDisabled:
		return StatusDisabled, true
	case userref.StatusPendingDeletion:
		return StatusPendingDeletion, true
	default:
		return "", false
	}
}
