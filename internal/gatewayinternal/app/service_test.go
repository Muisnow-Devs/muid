package app

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	authnpb "sanzi.io/muid/api/proto/authn/v1"
	authzpb "sanzi.io/muid/api/proto/authz/v1"
	"sanzi.io/muid/infra/mocked"
	"sanzi.io/muid/pkg/gateway/httpmeta"
	"sanzi.io/muid/pkg/gateway/jwtauth"
)

const testIssuer = "https://id.test"

type fakeAuthzAdmin struct {
	authzpb.AuthzAdminServiceClient
	gotUserID string
}

func (f *fakeAuthzAdmin) ListCasbinRules(ctx context.Context, _ *authzpb.ListCasbinRulesRequest, _ ...grpc.CallOption) (*authzpb.ListCasbinRulesResponse, error) {
	if md, ok := metadata.FromOutgoingContext(ctx); ok {
		if v := md.Get(httpmeta.UserIDKey); len(v) == 1 {
			f.gotUserID = v[0]
		}
	}
	resp := &authzpb.ListCasbinRulesResponse{}
	resp.SetRevisionId("rev-1")
	return resp, nil
}

type fakeOIDCAdmin struct {
	authnpb.OIDCClientAdminServiceClient
}

type staticKeySource struct{ keys map[string]*rsa.PublicKey }

func (s staticKeySource) Keys(context.Context) (map[string]*rsa.PublicKey, error) {
	return s.keys, nil
}

func mintToken(t *testing.T, key *rsa.PrivateKey, kid, sub string) string {
	t.Helper()
	claims := jwt.MapClaims{
		"token_use": "session",
		"sub":       sub,
		"iss":       testIssuer,
		"iat":       jwt.NewNumericDate(time.Now()),
		"exp":       jwt.NewNumericDate(time.Now().Add(2 * time.Minute)),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["typ"] = "muid-session+jwt"
	token.Header["kid"] = kid
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}

func buildHandler(t *testing.T, authz *fakeAuthzAdmin) (http.Handler, *rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	kid := uuid.NewString()
	verifier := jwtauth.NewVerifier(
		staticKeySource{keys: map[string]*rsa.PublicKey{kid: &key.PublicKey}},
		jwtauth.Config{Issuer: testIssuer},
	)
	infra := &InfraDependencies{
		GlobalConfig: Config{Port: 8082, RateLimit: 100, RateLimitWindowSeconds: 60, RiskBlockThreshold: 100, SessionAccessTokenIssuer: testIssuer},
		Redis:        mocked.NewMockKVStore(),
		Verifier:     verifier,
		OIDCAdmin:    &fakeOIDCAdmin{},
		AuthzAdmin:   authz,
	}
	return newHandler(infra), key, kid
}

func TestHealthIsOpen(t *testing.T) {
	t.Parallel()

	h, _, _ := buildHandler(t, &fakeAuthzAdmin{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("healthz = %d", rec.Code)
	}
}

func TestAdminRequiresToken(t *testing.T) {
	t.Parallel()

	h, _, _ := buildHandler(t, &fakeAuthzAdmin{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/authz/casbin-rules", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("admin without token = %d, want 401", rec.Code)
	}
}

func TestAdminAllowlistRejectsNonAdmin(t *testing.T) {
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	kid := uuid.NewString()
	verifier := jwtauth.NewVerifier(
		staticKeySource{keys: map[string]*rsa.PublicKey{kid: &key.PublicKey}},
		jwtauth.Config{Issuer: testIssuer},
	)
	admin := uuid.NewString()
	infra := &InfraDependencies{
		GlobalConfig: Config{Port: 8082, RateLimit: 100, RateLimitWindowSeconds: 60, RiskBlockThreshold: 100, SessionAccessTokenIssuer: testIssuer, AdminUserIDs: []string{admin}},
		Redis:        mocked.NewMockKVStore(),
		Verifier:     verifier,
		OIDCAdmin:    &fakeOIDCAdmin{},
		AuthzAdmin:   &fakeAuthzAdmin{},
	}
	h := newHandler(infra)

	// An authenticated but non-allowlisted caller is forbidden.
	req := httptest.NewRequest(http.MethodGet, "/admin/authz/casbin-rules", nil)
	req.Header.Set("Authorization", "Bearer "+mintToken(t, key, kid, uuid.NewString()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin = %d, want 403", rec.Code)
	}

	// The allowlisted admin passes.
	req = httptest.NewRequest(http.MethodGet, "/admin/authz/casbin-rules", nil)
	req.Header.Set("Authorization", "Bearer "+mintToken(t, key, kid, admin))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("allowlisted admin = %d body=%s, want 200", rec.Code, rec.Body.String())
	}
}

func TestAdminForwardsIdentity(t *testing.T) {
	t.Parallel()

	authz := &fakeAuthzAdmin{}
	h, key, kid := buildHandler(t, authz)
	sub := uuid.NewString()
	token := mintToken(t, key, kid, sub)

	req := httptest.NewRequest(http.MethodGet, "/admin/authz/casbin-rules?domain=*", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("admin with token = %d body=%s", rec.Code, rec.Body.String())
	}
	if authz.gotUserID != sub {
		t.Fatalf("authz received x-user-id %q, want %q", authz.gotUserID, sub)
	}
}
