package identity

import "errors"

var (
	ErrProviderExists   = errors.New("identity provider already exists")
	ErrProviderNotFound = errors.New("identity provider not found")
)
