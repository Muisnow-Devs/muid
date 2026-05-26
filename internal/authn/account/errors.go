package account

import "errors"

var (
	errProfileClientUnset = errors.New("authn: profile gRPC client is not configured")
	errOIDCEmailRequired  = errors.New("authn: OIDC identity token has no email; cannot register")
	errOIDCRegisterData   = errors.New("authn: incomplete OIDC register-required data")

	// ErrReauthenticationRequired is returned when a session is too old for a sensitive operation.
	ErrReauthenticationRequired = errors.New("reauthentication required")

	// ErrFederatedIdentityNotFound is returned when no active federated link exists for the user.
	ErrFederatedIdentityNotFound = errors.New("federated identity not found")

	// ErrFederatedSubjectLinkedToOtherUser is returned when provider+subject is already
	// linked to a different user (including soft-revoked rows; user_id is immutable).
	ErrFederatedSubjectLinkedToOtherUser = errors.New("federated subject linked to another user")
)
