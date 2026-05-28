package session

import "errors"

var (
	ErrSessionExpired        = errors.New("session has expired")
	ErrSessionAbsoluteExpiry = errors.New("session absolute expiry reached")
	ErrSessionNotFound       = errors.New("session not found")
	ErrSessionExists         = errors.New("session already exists")
	ErrProviderMismatch      = errors.New("cannot change session provider")

	// ErrInvalidWireSessionToken is returned when a session wire token string is malformed.
	ErrInvalidWireSessionToken = errors.New("invalid session token format")

	// ErrSessionCacheRejected is returned when a cache entry exists for the token's selector
	// but the wire token validator does not match the cached snapshot. Session resolution
	// must not fall through to database lookup.
	ErrSessionCacheRejected = errors.New("session cache rejected token")
)
