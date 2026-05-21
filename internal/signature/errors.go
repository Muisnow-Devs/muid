package signature

import "errors"

var (
	// ErrInvalidConfig indicates SignatureManager was configured without required settings.
	ErrInvalidConfig = errors.New("signature: invalid config")
	// ErrInvalidKey indicates a signing key payload cannot be parsed or used.
	ErrInvalidKey = errors.New("signature: invalid key")
	// ErrKeyNotFound indicates the requested key id is not known to the manager.
	ErrKeyNotFound = errors.New("signature: key not found")
	// ErrSecretUnavailable indicates the backing SecretManager could not provide a required secret.
	ErrSecretUnavailable = errors.New("signature: secret unavailable")
	// ErrSignFailed indicates signing failed after a key was selected.
	ErrSignFailed = errors.New("signature: sign failed")
	// ErrValidateFailed indicates signature validation could not be completed.
	ErrValidateFailed = errors.New("signature: validate failed")
	// ErrPublicKeyUnavailable indicates public key material could not be built.
	ErrPublicKeyUnavailable = errors.New("signature: public key unavailable")
	// ErrRotateFailed indicates key rotation failed.
	ErrRotateFailed = errors.New("signature: rotate failed")
	// ErrRevokeFailed indicates key revocation failed.
	ErrRevokeFailed = errors.New("signature: revoke failed")
	// ErrUnsupportedAlgorithm indicates the requested signature algorithm is not supported.
	ErrUnsupportedAlgorithm = errors.New("signature: unsupported algorithm")
)
