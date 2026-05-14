package app

// Stable machine-oriented error_code values for [ContinueAuthSessionResponse] failures.
const (
	ErrCodeOIDCManualLinkRequired = "muid.authn.oidc_manual_account_linking_required"
	ErrCodePasskeyNotLinked       = "muid.authn.passkey_credential_not_linked"
	ErrCodeAuthenticationFailed   = "muid.authn.authentication_failed"
	ErrCodeInvalidInput           = "muid.authn.invalid_input"
)
