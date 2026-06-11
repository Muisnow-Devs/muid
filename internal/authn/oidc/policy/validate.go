package policy

import (
	"errors"
	"slices"

	"sanzi.io/muid/internal/authn/ent"
	"sanzi.io/muid/internal/authn/ent/oidcclient"
)

const (
	// ResponseTypeCode is the only supported response_type.
	ResponseTypeCode = "code"
	// CodeChallengeMethodS256 is the only supported PKCE method; "plain" is
	// deliberately rejected.
	CodeChallengeMethodS256 = "S256"
)

var (
	// ErrRedirectURINotRegistered maps to gRPC InvalidArgument: the gateway
	// must render an error page, never redirect.
	ErrRedirectURINotRegistered = errors.New("oidc policy: redirect uri not registered")
	// ErrUnsupportedResponseType maps to unsupported_response_type.
	ErrUnsupportedResponseType = errors.New("oidc policy: unsupported response type")
	// ErrPKCERequired maps to invalid_request: public clients must send a
	// code challenge.
	ErrPKCERequired = errors.New("oidc policy: pkce required")
	// ErrPKCEMethodUnsupported maps to invalid_request.
	ErrPKCEMethodUnsupported = errors.New("oidc policy: pkce method unsupported")
	// ErrGrantTypeNotEnabled maps to unauthorized_client: the grant type is
	// not enabled for this client.
	ErrGrantTypeNotEnabled = errors.New("oidc policy: grant type not enabled")
)

// Client grant_types values (stored in the Ent grant_types column).
const (
	GrantTypeAuthorizationCode = "authorization_code"
	GrantTypeRefreshToken      = "refresh_token"
	GrantTypeDeviceCode        = "device_code"
)

// ValidateAuthorizeRequest checks the request-shaped parts of an Authorize
// call: registered redirect URI (exact string match), response type, and the
// PKCE rules implied by the client type.
func ValidateAuthorizeRequest(
	client *ent.OIDCClient,
	registeredURIs []string,
	redirectURI string,
	responseType string,
	codeChallenge string,
	codeChallengeMethod string,
) error {
	if !slices.Contains(registeredURIs, redirectURI) {
		return ErrRedirectURINotRegistered
	}
	if responseType != ResponseTypeCode {
		return ErrUnsupportedResponseType
	}
	return validatePKCE(client, codeChallenge, codeChallengeMethod)
}

func validatePKCE(client *ent.OIDCClient, codeChallenge, codeChallengeMethod string) error {
	public := client.TokenEndpointAuthMethod == oidcclient.TokenEndpointAuthMethodNone
	if codeChallenge == "" {
		if public {
			return ErrPKCERequired
		}
		return nil
	}
	if codeChallengeMethod != CodeChallengeMethodS256 {
		return ErrPKCEMethodUnsupported
	}
	return nil
}

// GrantTypeEnabled checks that the client opted in to the given grant type.
func GrantTypeEnabled(client *ent.OIDCClient, grantType string) error {
	if !slices.Contains(client.GrantTypes, grantType) {
		return ErrGrantTypeNotEnabled
	}
	return nil
}
