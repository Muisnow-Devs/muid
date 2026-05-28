package authn

// Error codes for the Authn service, following the `service.namespace.code` format.
const (
	ErrCodeLinkUnauthorized         = "authn.link.unauthorized"
	ErrCodeEmailAlreadyInUse        = "authn.email.already_in_use"
	ErrCodeAuthenticationFailed     = "authn.authentication.failed"
	ErrCodeOIDCManualLinkRequired   = "authn.oidc.manual_link_required"
	ErrCodePasskeyAlreadyRegistered = "authn.passkey.already_registered"
	ErrCodeTransitionNotFound       = "authn.transition.not_found"
	ErrCodeTransitionExpired        = "authn.transition.expired"
	ErrCodeInvalidSessionState      = "authn.session.invalid_state"
	ErrCodeInvalidInput             = "authn.input.invalid"
	ErrCodeRateLimited              = "authn.rate.limited"
)
