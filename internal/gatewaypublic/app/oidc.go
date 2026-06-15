package app

import (
	"net/http"
	"strings"

	authnpb "sanzi.io/muid/api/proto/authn/v1"
	"sanzi.io/muid/internal/gatewaypublic/reqctx"
	"sanzi.io/muid/pkg/gateway/httpmeta"
	"sanzi.io/muid/pkg/gateway/httpx"
	"sanzi.io/muid/pkg/log"
)

// oidcHandlers maps the OIDC/JWKS REST surface onto authn gRPC. OAuth protocol
// failures are returned as response data (never gRPC-error leakage), matching
// the proto contract.
type oidcHandlers struct {
	oidc  authnpb.OIDCServiceClient
	authn authnpb.AuthnServiceClient
}

func newOIDCHandlers(deps *InfraDependencies) *oidcHandlers {
	return &oidcHandlers{oidc: deps.OIDCClient, authn: deps.AuthnClient}
}

// discoveryDocument mirrors the OIDC discovery JSON. Field names match the
// proto, which is itself shaped to serialize verbatim.
type discoveryDocument struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	DeviceAuthorizationEndpoint       string   `json:"device_authorization_endpoint,omitempty"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint"`
	JWKSURI                           string   `json:"jwks_uri"`
	ScopesSupported                   []string `json:"scopes_supported,omitempty"`
	ResponseTypesSupported            []string `json:"response_types_supported,omitempty"`
	GrantTypesSupported               []string `json:"grant_types_supported,omitempty"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported,omitempty"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported,omitempty"`
	SubjectTypesSupported             []string `json:"subject_types_supported,omitempty"`
}

func (h *oidcHandlers) discovery(w http.ResponseWriter, r *http.Request) {
	resp, err := h.oidc.GetProviderMetadata(reqctx.OutgoingMetadata(r.Context()), &authnpb.GetProviderMetadataRequest{})
	if err != nil {
		writeUpstreamError(w, r, err)
		return
	}
	httpx.JSON(w, r, http.StatusOK, discoveryDocument{
		Issuer:                            resp.GetIssuer(),
		AuthorizationEndpoint:             resp.GetAuthorizationEndpoint(),
		TokenEndpoint:                     resp.GetTokenEndpoint(),
		DeviceAuthorizationEndpoint:       resp.GetDeviceAuthorizationEndpoint(),
		UserinfoEndpoint:                  resp.GetUserinfoEndpoint(),
		JWKSURI:                           resp.GetJwksUri(),
		ScopesSupported:                   resp.GetScopesSupported(),
		ResponseTypesSupported:            resp.GetResponseTypesSupported(),
		GrantTypesSupported:               resp.GetGrantTypesSupported(),
		CodeChallengeMethodsSupported:     resp.GetCodeChallengeMethodsSupported(),
		TokenEndpointAuthMethodsSupported: resp.GetTokenEndpointAuthMethodsSupported(),
		IDTokenSigningAlgValuesSupported:  resp.GetIdTokenSigningAlgValuesSupported(),
		SubjectTypesSupported:             resp.GetSubjectTypesSupported(),
	})
}

// jwk is a single JSON Web Key. n/e are base64url per RFC 7517.
type jwk struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg,omitempty"`
	Use string `json:"use,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

func (h *oidcHandlers) jwks(w http.ResponseWriter, r *http.Request) {
	resp, err := h.authn.GetPublicKeys(reqctx.OutgoingMetadata(r.Context()), &authnpb.GetPublicKeysRequest{})
	if err != nil {
		writeUpstreamError(w, r, err)
		return
	}
	keys := make([]jwk, 0, len(resp.GetPublicKeys()))
	for _, pk := range resp.GetPublicKeys() {
		keys = append(keys, jwk{
			Kid: pk.GetKid(), Kty: pk.GetKty(), Alg: pk.GetAlg(), Use: pk.GetUse(),
			N: pk.GetN(), E: pk.GetE(), Crv: pk.GetCrv(), X: pk.GetX(), Y: pk.GetY(),
		})
	}
	httpx.JSON(w, r, http.StatusOK, map[string]any{"keys": keys})
}

// token maps POST /token form parameters onto OIDCService.ExchangeToken.
func (h *oidcHandlers) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid_request", "malformed form body")
		return
	}

	clientID, clientSecret := clientCredentials(r)
	req := &authnpb.ExchangeTokenRequest{}
	req.SetClientId(clientID)
	if clientSecret != "" {
		req.SetClientSecret(clientSecret)
	}

	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		grant := &authnpb.AuthorizationCodeGrant{}
		grant.SetCode(r.PostForm.Get("code"))
		grant.SetRedirectUri(r.PostForm.Get("redirect_uri"))
		grant.SetCodeVerifier(r.PostForm.Get("code_verifier"))
		req.SetAuthorizationCode(grant)
	case "refresh_token":
		grant := &authnpb.RefreshTokenGrant{}
		grant.SetRefreshToken(r.PostForm.Get("refresh_token"))
		if scope := strings.TrimSpace(r.PostForm.Get("scope")); scope != "" {
			grant.SetScopes(strings.Fields(scope))
		}
		req.SetRefreshToken(grant)
	default:
		httpx.Error(w, http.StatusBadRequest, "unsupported_grant_type", "unsupported grant_type")
		return
	}

	resp, err := h.oidc.ExchangeToken(reqctx.OutgoingMetadata(r.Context()), req)
	if err != nil {
		writeUpstreamError(w, r, err)
		return
	}
	if resp.HasError() {
		oauthErr := resp.GetError()
		httpx.Error(w, oauthStatus(oauthErr.GetError()), oauthErr.GetError(), oauthErr.GetErrorDescription())
		return
	}

	success := resp.GetSuccess()
	body := map[string]any{
		"access_token": success.GetAccessToken(),
		"token_type":   success.GetTokenType(),
		"expires_in":   success.GetExpiresIn(),
	}
	if v := success.GetRefreshToken(); v != "" {
		body["refresh_token"] = v
	}
	if v := success.GetIdToken(); v != "" {
		body["id_token"] = v
	}
	if scopes := success.GetScopes(); len(scopes) > 0 {
		body["scope"] = strings.Join(scopes, " ")
	}
	w.Header().Set("Cache-Control", "no-store")
	httpx.JSON(w, r, http.StatusOK, body)
}

// userinfo maps GET/POST /userinfo onto OIDCService.GetUserInfo, taking the
// access token from the Bearer Authorization header.
func (h *oidcHandlers) userinfo(w http.ResponseWriter, r *http.Request) {
	token := httpmeta.BearerToken(r.Header.Get("Authorization"))
	if token == "" {
		w.Header().Set("WWW-Authenticate", "Bearer")
		httpx.Error(w, http.StatusUnauthorized, "invalid_token", "missing bearer token")
		return
	}

	req := &authnpb.GetUserInfoRequest{}
	req.SetAccessToken(token)
	resp, err := h.oidc.GetUserInfo(reqctx.OutgoingMetadata(r.Context()), req)
	if err != nil {
		writeUpstreamError(w, r, err)
		return
	}
	if resp.HasError() {
		oauthErr := resp.GetError()
		w.Header().Set("WWW-Authenticate", "Bearer error=\""+oauthErr.GetError()+"\"")
		httpx.Error(w, http.StatusUnauthorized, oauthErr.GetError(), oauthErr.GetErrorDescription())
		return
	}

	info := resp.GetUserInfo()
	body := map[string]any{"sub": info.GetSub()}
	if info.HasName() {
		body["name"] = info.GetName()
	}
	if info.HasPreferredUsername() {
		body["preferred_username"] = info.GetPreferredUsername()
	}
	if info.HasPicture() {
		body["picture"] = info.GetPicture()
	}
	if info.HasEmail() {
		body["email"] = info.GetEmail()
	}
	if info.HasEmailVerified() {
		body["email_verified"] = info.GetEmailVerified()
	}
	if info.HasLocale() {
		body["locale"] = info.GetLocale()
	}
	if info.HasZoneinfo() {
		body["zoneinfo"] = info.GetZoneinfo()
	}
	httpx.JSON(w, r, http.StatusOK, body)
}

// clientCredentials extracts client_id/secret from HTTP Basic auth, falling
// back to the form-encoded client_secret_post fields.
func clientCredentials(r *http.Request) (id, secret string) {
	if user, pass, ok := r.BasicAuth(); ok {
		return user, pass
	}
	return r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
}

// oauthStatus maps an OAuth error code to an HTTP status.
func oauthStatus(code string) int {
	switch code {
	case "invalid_client":
		return http.StatusUnauthorized
	default:
		return http.StatusBadRequest
	}
}

// writeUpstreamError renders a transport/internal upstream failure without
// leaking the raw gRPC error to the client.
func writeUpstreamError(w http.ResponseWriter, r *http.Request, err error) {
	log.LogUnexpected(r.Context(), "gateway upstream call failed", err.Error())
	httpx.Error(w, http.StatusBadGateway, "upstream_error", "upstream service error")
}
