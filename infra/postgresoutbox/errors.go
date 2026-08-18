// Package postgresoutbox provides a PostgreSQL-backed outbox store.
package postgresoutbox

import "errors"

var (
	// ErrInvalidConfig indicates an invalid store dependency or method input.
	ErrInvalidConfig = errors.New("postgres outbox: invalid config")
	// ErrLeaseLost indicates an outbox event is no longer owned by the supplied lease.
	ErrLeaseLost = errors.New("postgres outbox: lease lost")
)
