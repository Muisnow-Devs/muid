package authn

import "errors"

// Error codes for the Authn service, following the `service.namespace.code` format.
// Only codes that are embedded in an AuthFailure response body belong here.
// Structural failures that map to a standard gRPC status code (codes.NotFound,
// codes.ResourceExhausted, …) are returned as gRPC errors directly by the handler.
var (
	ErrInternal   = errors.New("authn: internal error")
	ErrUserFacing = errors.New("authn: user-facing error")

	ErrCodeLinkUnauthorized         = "authn.link.unauthorized"
	ErrCodeEmailAlreadyInUse        = "authn.email.already_in_use"
	ErrCodeAuthenticationFailed     = "authn.authentication.failed"
	ErrCodeOIDCManualLinkRequired   = "authn.oidc.manual_link_required"
	ErrCodePasskeyAlreadyRegistered = "authn.passkey.already_registered"
	ErrCodeInvalidSessionState      = "authn.session.invalid_state"
	ErrCodeInvalidInput             = "authn.input.invalid"
	ErrCodeRateLimited              = "authn.rate.limited"
)
