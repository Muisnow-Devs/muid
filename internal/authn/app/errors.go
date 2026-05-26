package app

// OIDCProviderInitError records a failure while constructing a named OIDC provider.
type OIDCProviderInitError struct {
	Name string
	Err  error
}

func (e *OIDCProviderInitError) Error() string {
	return "authn app: create OIDC provider " + e.Name + ": " + e.Err.Error()
}

func (e *OIDCProviderInitError) Unwrap() error { return e.Err }
