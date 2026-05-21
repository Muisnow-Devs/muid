package account

import (
	"context"

	"github.com/google/uuid"
	sessionpb "sanzi.io/muid/api/proto/authn/v1/session"
	"sanzi.io/muid/internal/identity"
	"sanzi.io/muid/pkg/shared/pubsub"
)

// Provisioning creates new users from register-required signup data.
type Provisioning interface {
	ProvisionUser(ctx context.Context, reg *identity.RegisterRequired) (uuid.UUID, error)
}

// Email covers email lookup and email change.
type Email interface {
	LookupUserByEmail(ctx context.Context, email string) (uuid.UUID, bool, error)
	ChangeUserEmail(
		ctx context.Context,
		pub pubsub.PubSub,
		userID uuid.UUID,
		newEmail string,
	) (oldEmail string, err error)
}

// OIDC covers federated identity lookup and OIDC signup provisioning.
type OIDC interface {
	LookupOIDCLogin(
		ctx context.Context,
		providerName, subject, email string,
		emailVerified bool,
		displayName, picture string,
	) (uuid.UUID, *identity.RegisterRequired, error)
}

// Passkey persists WebAuthn credentials and related notifications.
type Passkey interface {
	LinkPasskey(
		ctx context.Context,
		pub pubsub.PubSub,
		userID uuid.UUID,
		credentialID, publicKey []byte,
		rpID, deviceType, name string,
	) error
}

// Session issues, resolves, and revokes authenticated sessions.
type Session interface {
	IssueAuthenticatedSession(
		ctx context.Context,
		userID uuid.UUID,
	) (*sessionpb.AuthenticatedResult, error)
	ResolveSessionToken(ctx context.Context, wireToken string) (ResolvedSession, error)
	RevokeSessionToken(ctx context.Context, wireToken string) error
	AuthenticatedResultFromResolved(
		wireToken string,
		resolved ResolvedSession,
	) *sessionpb.AuthenticatedResult
}
