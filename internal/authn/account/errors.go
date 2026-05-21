package account

import "errors"

var (
	errProfileClientUnset = errors.New("authn: profile gRPC client is not configured")
	errOIDCEmailRequired  = errors.New("authn: OIDC identity token has no email; cannot register")
	errOIDCRegisterData   = errors.New("authn: incomplete OIDC register-required data")
)
