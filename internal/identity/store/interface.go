package store

import (
	"context"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
)

// Identity is the unified identity record returned by all per-method stores.
type Identity struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	Provider  string
	Subject   string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// IdentityStore is the common interface implemented by each method-specific store.
// FindUser and LinkIdentity use the same surface across all methods; each
// implementation knows how to interpret the arguments for its method.
type IdentityStore interface {
	// FindUser returns the active (non-revoked) UserIdentity for the given
	// provider + subject, or (nil, nil) when not found.
	FindUser(ctx context.Context, provider, subject string) (*Identity, error)

	// LinkIdentity atomically creates the UserIdentity and the method-specific
	// sub-table row in a single transaction. Claims must be the correct concrete
	// type for the store (e.g. EmailIdentityClaims for the email store).
	LinkIdentity(ctx context.Context, userID uuid.UUID, claims IdentityClaims) (*Identity, error)

	// UpdateLastUsed marks the identity as recently used.
	UpdateLastUsed(ctx context.Context, identityID uuid.UUID) error

	// RevokeIdentity marks the identity (and any sub-table row) as revoked.
	RevokeIdentity(ctx context.Context, identityID uuid.UUID) error
}

// PasskeyCeremonyUser is a WebAuthn user loaded from the database. It implements
// webauthn.User so that it can be passed directly to webauthn.WebAuthn ceremony
// helpers without the method package needing a database dependency.
type PasskeyCeremonyUser struct {
	ID          uuid.UUID
	Email       string
	Credentials []webauthn.Credential
}

func (u *PasskeyCeremonyUser) WebAuthnID() []byte                         { return u.ID[:] }
func (u *PasskeyCeremonyUser) WebAuthnName() string                       { return u.Email }
func (u *PasskeyCeremonyUser) WebAuthnDisplayName() string                { return u.Email }
func (u *PasskeyCeremonyUser) WebAuthnCredentials() []webauthn.Credential { return u.Credentials }

// PasskeyIdentityStore extends IdentityStore with the ceremony-user queries
// that the passkey method needs to drive WebAuthn registration and
// discoverable-login ceremonies without touching the database itself.
type PasskeyIdentityStore interface {
	IdentityStore

	// LoadCeremonyUser loads the WebAuthn user (email + active credentials)
	// for the given user ID.
	LoadCeremonyUser(ctx context.Context, userID uuid.UUID) (*PasskeyCeremonyUser, error)

	// FindCeremonyUserByCredential finds the ceremony user associated with a
	// raw credential ID (used during discoverable login).
	FindCeremonyUserByCredential(
		ctx context.Context,
		credentialID []byte,
	) (*PasskeyCeremonyUser, error)
}
