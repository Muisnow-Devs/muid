package store

import "sanzi.io/muid/internal/authn/ent"

// identityFromRow converts an ent.UserIdentity row to the store.Identity type.
func identityFromRow(row *ent.UserIdentity) *Identity {
	return &Identity{
		ID:        row.ID,
		UserID:    row.UserID,
		Provider:  row.Provider,
		Subject:   row.Subject,
		CreatedAt: row.CreatedAt,
		UpdatedAt: row.UpdatedAt,
	}
}
