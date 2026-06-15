package turnstile

import "errors"

var (
	// ErrMissingSecret is returned when constructing a verifier without a secret key.
	ErrMissingSecret = errors.New("turnstile: secret key required")
	// ErrMissingToken is returned when Verify is called with an empty token.
	ErrMissingToken = errors.New("turnstile: empty response token")
	// ErrUnexpectedStatus is returned for non-200 responses from the verify API.
	ErrUnexpectedStatus = errors.New("turnstile: unexpected verify status")
)
