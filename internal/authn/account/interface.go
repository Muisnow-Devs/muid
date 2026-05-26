package account

import (
	"context"
	"time"

	"github.com/google/uuid"
	sessionpb "sanzi.io/muid/api/proto/authn/v1/session"
	"sanzi.io/muid/internal/identity"
	"sanzi.io/muid/pkg/shared/pubsub"
)

// Provisioning creates new users from register-required signup data.
type Provisioning interface {
	ProvisionUser(ctx context.Context, reg *identity.RegisterRequired) (uuid.UUID, error)
}

// Email covers email lookup, user email reads, and email change.
type Email interface {
	LookupUserByEmail(ctx context.Context, email string) (uuid.UUID, bool, error)
	UserEmail(ctx context.Context, userID uuid.UUID) (string, error)
	EmailUsedByOther(ctx context.Context, email string, excludeUserID uuid.UUID) (bool, error)
	ChangeUserEmail(
		ctx context.Context,
		pub pubsub.PubSub,
		userID uuid.UUID,
		newEmail string,
		mailPrefs MailDeliveryPrefs,
	) (oldEmail string, err error)
}

// OIDC covers federated identity lookup for OIDC providers.
type OIDC interface {
	// LookupOIDCFederatedUser returns the user id when provider+subject is actively linked.
	LookupOIDCFederatedUser(
		ctx context.Context,
		providerName, subject string,
	) (uuid.UUID, bool, error)
	// LookupOIDCLogin resolves an OIDC subject to an existing user or register-required data.
	// When the federated subject is not linked, register-required claims are returned even if the
	// email already exists; login-flow orchestration decides manual linking vs provision.
	LookupOIDCLogin(
		ctx context.Context,
		providerName, subject, email string,
		emailVerified bool,
		displayName, picture string,
	) (uuid.UUID, *identity.RegisterRequired, error)
}

// Federated manages linked OIDC provider identities for existing users.
type Federated interface {
	LinkFederatedIdentity(ctx context.Context, params FederatedLinkParams) error
	RevokeFederatedIdentity(ctx context.Context, userID uuid.UUID, provider string) error
}

// Passkey persists WebAuthn credentials and related notifications.
type LinkPasskeyConfig struct {
	UserId         uuid.UUID
	CredentialID   []byte
	PublicKey      []byte
	RpID           string
	DeviceType     string
	Name           string
	BackupEligible bool
	BackupState    bool
	SignCount      uint32
	Transports     []string
	AAGUID         []byte
}

type UpdatePasskeyUsageConfig struct {
	CredentialID []byte
	BackupState  bool
	SignCount    uint32
	LastUsedAt   time.Time
}

type Passkey interface {
	LinkPasskey(
		ctx context.Context,
		config LinkPasskeyConfig,
	) error
	UpdatePasskeyUsage(
		ctx context.Context,
		config UpdatePasskeyUsageConfig,
	) error
	LoadCeremonyUser(ctx context.Context, userID uuid.UUID) (*PasskeyCeremonyUser, error)
	LoadCeremonyUserDiscoverable(
		ctx context.Context,
		credentialID, userHandle []byte,
	) (*PasskeyCeremonyUser, error)
}

// Session issues, resolves, and revokes authenticated sessions.
type Session interface {
	IssueAuthenticatedSession(
		ctx context.Context,
		userID uuid.UUID,
	) (*sessionpb.AuthenticatedResult, error)
	ResolveSessionToken(ctx context.Context, wireToken string) (ResolvedSession, error)
	SessionCreatedAt(ctx context.Context, sessionID uuid.UUID) (time.Time, error)
	RevokeSessionToken(ctx context.Context, wireToken string) error
	AuthenticatedResultFromResolved(
		wireToken string,
		resolved ResolvedSession,
	) *sessionpb.AuthenticatedResult
	AuthenticatedPrincipalFromResolved(
		resolved ResolvedSession,
	) *sessionpb.AuthenticatedPrincipal
}
