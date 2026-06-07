package session

import (
	"errors"
	"fmt"
)

var (
	ErrSession = errors.New("session")

	ErrSessionValidationFailed = fmt.Errorf("%w: validation failed", ErrSession)
	ErrSessionStorageFailed    = fmt.Errorf("%w: storage failed", ErrSession)
	ErrInvalidWireSessionToken = fmt.Errorf("%w: invalid session token format", ErrSession)

	ErrSessionExpired        = fmt.Errorf("%w: expired", ErrSessionValidationFailed)
	ErrSessionAbsoluteExpiry = fmt.Errorf("%w: absolute expiry", ErrSessionValidationFailed)
	ErrSessionNotFound       = fmt.Errorf("%w: not found", ErrSessionValidationFailed)
	ErrSessionCacheRejected  = fmt.Errorf("%w: cache rejected token", ErrSessionValidationFailed)
	ErrProviderMismatch      = fmt.Errorf("%w: provider mismatch", ErrSessionValidationFailed)

	ErrSessionExists = fmt.Errorf("%w: already exists", ErrSessionStorageFailed)
)
