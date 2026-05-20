package secretmanager

import "errors"

var (
	// ErrInvalidSecretRef indicates Name or Version failed validation.
	ErrInvalidSecretRef = errors.New("secretmanager: invalid secret ref")
	// ErrEmptyProjectID indicates a backend requires a project id for short secret ids.
	ErrEmptyProjectID = errors.New("secretmanager: empty project id")
	// ErrSecretNotFound indicates the secret resource does not exist.
	ErrSecretNotFound = errors.New("secretmanager: secret not found")
	// ErrVersionNotFound indicates the requested version does not exist.
	ErrVersionNotFound = errors.New("secretmanager: secret version not found")
	// ErrVersionDisabled indicates the version is disabled or destroyed.
	ErrVersionDisabled = errors.New("secretmanager: secret version disabled")
)

// IsNotFound reports whether err is [ErrSecretNotFound] or [ErrVersionNotFound].
func IsNotFound(err error) bool {
	return errors.Is(err, ErrSecretNotFound) || errors.Is(err, ErrVersionNotFound)
}
