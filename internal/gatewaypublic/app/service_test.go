package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"google.golang.org/grpc"

	authnpb "sanzi.io/muid/api/proto/authn/v1"
	"sanzi.io/muid/infra/geoip"
	"sanzi.io/muid/infra/mocked"
	"sanzi.io/muid/infra/turnstile"
	"sanzi.io/muid/pkg/gateway/csrf"
)

// fakeOIDC implements only the OIDCServiceClient methods the gateway uses.
type fakeOIDC struct {
	authnpb.OIDCServiceClient
}

func (fakeOIDC) GetProviderMetadata(context.Context, *authnpb.GetProviderMetadataRequest, ...grpc.CallOption) (*authnpb.GetProviderMetadataResponse, error) {
	resp := &authnpb.GetProviderMetadataResponse{}
	resp.SetIssuer("https://id.test")
	resp.SetTokenEndpoint("https://id.test/oidc/token")
	resp.SetJwksUri("https://id.test/.well-known/jwks.json")
	return resp, nil
}

func (fakeOIDC) ExchangeToken(_ context.Context, req *authnpb.ExchangeTokenRequest, _ ...grpc.CallOption) (*authnpb.ExchangeTokenResponse, error) {
	resp := &authnpb.ExchangeTokenResponse{}
	if req.GetClientId() == "bad" {
		oerr := &authnpb.OAuthError{}
		oerr.SetError("invalid_client")
		oerr.SetErrorDescription("unknown client")
		resp.SetError(oerr)
		return resp, nil
	}
	ok := &authnpb.TokenSuccess{}
	ok.SetAccessToken("at-123")
	ok.SetTokenType("Bearer")
	ok.SetExpiresIn(300)
	resp.SetSuccess(ok)
	return resp, nil
}

// fakeAuthn implements only AuthnServiceClient.GetPublicKeys.
type fakeAuthn struct {
	authnpb.AuthnServiceClient
}

func (fakeAuthn) GetPublicKeys(context.Context, *authnpb.GetPublicKeysRequest, ...grpc.CallOption) (*authnpb.GetPublicKeysResponse, error) {
	return &authnpb.GetPublicKeysResponse{}, nil
}

func testInfra(t *testing.T, cfg Config, geoInfo geoip.GeoInfo) *InfraDependencies {
	t.Helper()
	csrfMgr, err := csrf.New([]byte("test-secret"), 0)
	if err != nil {
		t.Fatalf("csrf: %v", err)
	}
	return &InfraDependencies{
		GlobalConfig: cfg,
		Redis:        mocked.NewMockKVStore(),
		Geo:          geoip.NewMockResolver(geoInfo),
		Turnstile:    turnstile.AlwaysValid(),
		CSRF:         csrfMgr,
		OIDCClient:   fakeOIDC{},
		AuthnClient:  fakeAuthn{},
	}
}

func defaultConfig() Config {
	return Config{
		// Debug allows ad-hoc operations so tests need no persisted manifest.
		Debug:                  true,
		Port:                   8080,
		RateLimit:              100,
		RateLimitWindowSeconds: 60,
		RiskPoWThreshold:       50,
		RiskBlockThreshold:     90,
		PoWDifficulty:          8,
	}
}

func TestHealthAndDiscovery(t *testing.T) {
	t.Parallel()

	h := newHandler(testInfra(t, defaultConfig(), geoip.GeoInfo{CountryCode: "US", Resolved: true}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("healthz = %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("discovery = %d", rec.Code)
	}
	var doc map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("discovery json: %v", err)
	}
	if doc["issuer"] != "https://id.test" {
		t.Fatalf("discovery issuer = %v", doc["issuer"])
	}
}

func TestTokenSuccessAndError(t *testing.T) {
	t.Parallel()

	h := newHandler(testInfra(t, defaultConfig(), geoip.GeoInfo{CountryCode: "US", Resolved: true}))

	form := url.Values{"grant_type": {"authorization_code"}, "client_id": {"good"}, "code": {"c"}}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("token success = %d body=%s", rec.Code, rec.Body.String())
	}

	badForm := url.Values{"grant_type": {"authorization_code"}, "client_id": {"bad"}, "code": {"c"}}
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(badForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("invalid_client should map to 401, got %d", rec.Code)
	}
}

func TestRiskBlocksByCountry(t *testing.T) {
	t.Parallel()

	cfg := defaultConfig()
	cfg.BlockedCountries = []string{"XX"}
	h := newHandler(testInfra(t, cfg, geoip.GeoInfo{CountryCode: "XX", Resolved: true}))

	rec := httptest.NewRecorder()
	// Health is intentionally outside the protector, so exercise a protected app
	// route to prove the risk policy blocks high-risk traffic.
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("blocked country should yield 403, got %d", rec.Code)
	}
}

func TestAccessTokenRequiresAllowedOrigin(t *testing.T) {
	t.Parallel()

	cfg := defaultConfig()
	cfg.CORSAllowedOrigins = []string{"https://app.example"}
	h := newHandler(testInfra(t, cfg, geoip.GeoInfo{CountryCode: "US", Resolved: true}))

	// Missing Origin is rejected when an allowlist is configured.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/security/access-token", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("missing Origin should be 403, got %d", rec.Code)
	}

	// A disallowed Origin is rejected.
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/security/access-token", nil)
	req.Header.Set("Origin", "https://evil.example")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("disallowed Origin should be 403, got %d", rec.Code)
	}

	// An allowed Origin passes the guard (then 401 without a session cookie).
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/security/access-token", nil)
	req.Header.Set("Origin", "https://app.example")
	h.ServeHTTP(rec, req)
	if rec.Code == http.StatusForbidden {
		t.Fatalf("allowed Origin should pass the origin guard, got 403")
	}
}

func TestCSRFEndpoint(t *testing.T) {
	t.Parallel()

	infra := testInfra(t, defaultConfig(), geoip.GeoInfo{CountryCode: "US", Resolved: true})
	h := newHandler(infra)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/security/csrf", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("csrf = %d", rec.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("csrf json: %v", err)
	}
	if err := infra.CSRF.Validate(body["csrf_token"]); err != nil {
		t.Fatalf("issued csrf token should validate: %v", err)
	}
}
