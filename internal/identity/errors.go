package identity

import "errors"

var (
	ErrProviderExists   = errors.New("identity provider already exists")
	ErrProviderNotFound = errors.New("identity provider not found")

	// Common identity flow errors
	ErrInvalidInput         = errors.New("invalid input payload")
	ErrSessionNotFound      = errors.New("authentication session not found")
	ErrInvalidSessionState  = errors.New("invalid session state")
	ErrAuthenticationFailed = errors.New("provider authentication failed")

	// ErrOIDCManualAccountLinkingRequired is returned when an OIDC identity is new
	// but the email already belongs to a manually-created (non-federated) account.
	ErrOIDCManualAccountLinkingRequired = errors.New(
		"muid.authn.oidc_manual_account_linking_required",
	)

	// ErrPasskeyNotLinked is returned when the presented WebAuthn credential is unknown.
	ErrPasskeyNotLinked = errors.New("muid.authn.passkey_credential_not_linked")

	// ErrLinkUnauthorized is returned when a linking flow lacks a valid session.
	ErrLinkUnauthorized = errors.New("linking requires a valid session")

	// ErrEmailAlreadyInUse is returned when the target email belongs to another user.
	ErrEmailAlreadyInUse = errors.New("email already in use")

	// ErrPasskeyAlreadyRegistered is returned when the credential id is already linked.
	ErrPasskeyAlreadyRegistered = errors.New("passkey credential already registered")
)
