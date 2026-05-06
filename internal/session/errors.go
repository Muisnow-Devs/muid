package session

import "errors"

var (
	ErrSessionExpired   = errors.New("session has expired")
	ErrSessionNotFound  = errors.New("session not found")
	ErrSessionExists    = errors.New("session already exists")
	ErrProviderMismatch = errors.New("cannot change session provider")
)
