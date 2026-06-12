package authzclient

import "errors"

var (
	// ErrNotStarted reports Enforce/IsMember before a successful Start.
	ErrNotStarted = errors.New("authzclient: enforcer not started")

	// ErrInvalidConfig reports a missing Namespace or Client.
	ErrInvalidConfig = errors.New("authzclient: invalid config")
)
