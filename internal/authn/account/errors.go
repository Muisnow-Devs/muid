package account

import "errors"

var (
	// ErrNotFound indicates that the requested account does not exist.
	ErrNotFound = errors.New("account not found")
	// ErrInvalidState indicates persisted account data violates account invariants.
	ErrInvalidState = errors.New("invalid account state")
)
