package oidc

import "errors"

// OAuth 2.0 / OIDC protocol error codes carried as response data.
const (
	ErrCodeInvalidRequest          = "invalid_request"
	ErrCodeInvalidClient           = "invalid_client"
	ErrCodeInvalidGrant            = "invalid_grant"
	ErrCodeUnauthorizedClient      = "unauthorized_client"
	ErrCodeUnsupportedGrantType    = "unsupported_grant_type"
	ErrCodeUnsupportedResponseType = "unsupported_response_type"
	ErrCodeInvalidScope            = "invalid_scope"
	ErrCodeAccessDenied            = "access_denied"
	ErrCodeAuthorizationPending    = "authorization_pending"
	ErrCodeSlowDown                = "slow_down"
	ErrCodeExpiredToken            = "expired_token"
	ErrCodeLoginRequired           = "login_required"
	ErrCodeConsentRequired         = "consent_required"
	ErrCodeInvalidToken            = "invalid_token"
	ErrCodeInsufficientScope       = "insufficient_scope"
)

// OAuthError is an OAuth protocol error. Handlers surface it as response
// data (pb.OAuthError), never as a gRPC error.
type OAuthError struct {
	Code        string
	Description string
}

func (e *OAuthError) Error() string {
	if e.Description == "" {
		return "oauth: " + e.Code
	}
	return "oauth: " + e.Code + ": " + e.Description
}

func oauthError(code, description string) *OAuthError {
	return &OAuthError{Code: code, Description: description}
}

// AsOAuthError unwraps err into an OAuthError when it is one.
func AsOAuthError(err error) (*OAuthError, bool) {
	var oauthErr *OAuthError
	ok := errors.As(err, &oauthErr)
	return oauthErr, ok
}

// Sentinels mapped to gRPC codes by the handler layer (cases where the spec
// forbids redirecting back to the client or the resource is simply gone).
var (
	// ErrClientNotFound: unknown client_id on Authorize (gRPC InvalidArgument).
	ErrClientNotFound = errors.New("oidc: client not found")
	// ErrRedirectURINotRegistered: gRPC InvalidArgument; the gateway must
	// render an error page rather than redirect.
	ErrRedirectURINotRegistered = errors.New("oidc: redirect uri not registered")
	// ErrPendingNotFound: unknown/expired/consumed pending authorization or
	// device user code (gRPC NotFound).
	ErrPendingNotFound = errors.New("oidc: pending authorization not found")
	// ErrWrongUser: the session user does not own the pending authorization
	// (gRPC PermissionDenied).
	ErrWrongUser = errors.New("oidc: authorization belongs to another user")
)
