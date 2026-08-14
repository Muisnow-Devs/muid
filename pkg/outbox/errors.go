package outbox

import "errors"

var (
	// ErrInvalidConfig indicates a relay was created without valid dependencies or configuration.
	ErrInvalidConfig = errors.New("outbox: invalid config")
	// ErrAlreadyStarted indicates Start was called after the relay worker was started.
	ErrAlreadyStarted = errors.New("outbox: relay already started")
)
