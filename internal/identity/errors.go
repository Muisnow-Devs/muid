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
	ErrInternal             = errors.New("internal error during identity processing")
)
