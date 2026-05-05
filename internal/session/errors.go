package session

import "errors"

var (
	ErrSessionExpired  = errors.New("session has expired")
	ErrSessionNotFound = errors.New("session not found")
)
