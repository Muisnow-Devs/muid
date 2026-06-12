package core

import "errors"

var (
	// ErrProfileNotFound is returned when the user profile row does not exist.
	ErrProfileNotFound = errors.New("profile not found")
	// ErrUsernameExhausted is returned when every generated username candidate is taken.
	ErrUsernameExhausted = errors.New("username candidates exhausted")
	// ErrUpdateConflict is returned when an update collides with a unique constraint (e.g. username taken).
	ErrUpdateConflict = errors.New("conflicting update value already in use")
	// ErrUnsupportedMaskPath is returned for update_mask paths outside the patchable allowlist.
	ErrUnsupportedMaskPath = errors.New("unsupported update_mask path")
	// ErrAvatarNotConfigured is returned from avatar RPC flows when R2 storage is not configured.
	ErrAvatarNotConfigured = errors.New("avatar storage not configured")
	// ErrAvatarSessionNotFound is returned when no UserAvatar row matches the upload session.
	ErrAvatarSessionNotFound = errors.New("avatar upload session not found")
	// ErrAvatarSessionCompleted is returned when the upload session was already completed.
	ErrAvatarSessionCompleted = errors.New("avatar upload session already completed")
	// ErrAvatarObjectMissing is returned when the staged object is absent from the upload bucket.
	ErrAvatarObjectMissing = errors.New("staging object not found")
	// ErrObjectKeyNotOwned is returned when the object key is outside the caller's namespace.
	ErrObjectKeyNotOwned = errors.New("object key does not belong to user")
	// ErrInvalidAvatarImage tags media validation/decode failures that are the client's fault.
	ErrInvalidAvatarImage = errors.New("invalid avatar image")
)

// InvalidArgumentError carries a client-safe message; the grpc layer maps it
// to codes.InvalidArgument verbatim.
type InvalidArgumentError struct {
	msg string
}

// NewInvalidArgumentError wraps a message that is safe to expose to clients.
func NewInvalidArgumentError(msg string) InvalidArgumentError {
	return InvalidArgumentError{msg: msg}
}

func (e InvalidArgumentError) Error() string { return e.msg }
