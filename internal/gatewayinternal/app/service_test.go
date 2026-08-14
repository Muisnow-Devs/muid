package app

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
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
	"sanzi.io/muid/pkg/shared/authzmodel"
)

const testIssuer = "https://id.test"

type fakeAuthzAdmin struct {
	authzpb.AuthzAdminServiceClient
	gotUserIDs []string
}

func (f *fakeAuthzAdmin) ListCasbinRules(ctx context.Context, _ *authzpb.ListCasbinRulesRequest, _ ...grpc.CallOption) (*authzpb.ListCasbinRulesResponse, error) {
	if md, ok := metadata.FromOutgoingContext(ctx); ok {
		f.gotUserIDs = append([]string(nil), md.Get(httpmeta.UserIDKey)...)
	}
	resp := &authzpb.ListCasbinRulesResponse{}
	resp.SetRevisionId("rev-1")
	return resp, nil
}

type fakeOIDCAdmin struct {
	authnpb.OIDCClientAdminServiceClient
}

type fakePlatformChecker struct {
	allowed        bool
	err            error
	gotUserID      uuid.UUID
	gotPermission  string
	gotMetadataIDs []string
}

func (f *fakePlatformChecker) CheckPermission(
	ctx context.Context,
	userID uuid.UUID,
	permission string,
) (bool, error) {
	f.gotUserID = userID
	f.gotPermission = permission
	if md, ok := metadata.FromOutgoingContext(ctx); ok {
		f.gotMetadataIDs = append([]string(nil), md.Get(httpmeta.UserIDKey)...)
	}
	return f.allowed, f.err
}

type staticKeySource struct{ keys map[string]*rsa.PublicKey }

func (s staticKeySource) Keys(context.Context) (map[string]*rsa.PublicKey, error) {
	return s.keys, nil
}

func mintToken(t *testing.T, key *rsa.PrivateKey, kid, sub string) string {
	return mintTokenWithExpiration(t, key, kid, sub, time.Now().Add(2*time.Minute))
}

func mintTokenWithExpiration(
	t *testing.T,
	key *rsa.PrivateKey,
	kid, sub string,
	expiresAt time.Time,
) string {
	t.Helper()
	claims := jwt.MapClaims{
		"token_use": "session",
		"sub":       sub,
		"iss":       testIssuer,
		"iat":       jwt.NewNumericDate(time.Now()),
		"exp":       jwt.NewNumericDate(expiresAt),
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

func buildHandler(
	t *testing.T,
	authz *fakeAuthzAdmin,
	checker platformPermissionChecker,
) (http.Handler, *rsa.PrivateKey, string) {
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
		PlatformAuthz: checker,
	}
	return newHandler(infra), key, kid
}

func TestHealthRequiresNoUserJWT(t *testing.T) {
	t.Parallel()

	h, _, _ := buildHandler(t, &fakeAuthzAdmin{}, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("healthz = %d", rec.Code)
	}
}

func TestNewAppRequiresIngressMTLS(t *testing.T) {
	t.Parallel()

	if _, err := NewApp(nil); err == nil {
		t.Fatal("NewApp(nil) accepted missing ingress mTLS")
	}
	if _, err := NewApp(&InfraDependencies{}); err == nil {
		t.Fatal("NewApp accepted a nil ingress TLS config")
	}
}

func TestAdminRequiresToken(t *testing.T) {
	t.Parallel()

	h, _, _ := buildHandler(t, &fakeAuthzAdmin{}, &fakePlatformChecker{allowed: true})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/authz/casbin-rules", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("admin without token = %d, want 401", rec.Code)
	}
}

func TestAdminUsesLivePlatformAuthorization(t *testing.T) {
	t.Parallel()

	checker := &fakePlatformChecker{}
	authz := &fakeAuthzAdmin{}
	h, key, kid := buildHandler(t, authz, checker)
	userID := uuid.New()
	req := httptest.NewRequest(http.MethodGet, "/admin/authz/casbin-rules", nil)
	req.Header.Set("Authorization", "Bearer "+mintToken(t, key, kid, userID.String()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("denied platform user = %d, want 403", rec.Code)
	}
	if len(authz.gotUserIDs) != 0 {
		t.Fatalf("denied request reached backend with identities %v", authz.gotUserIDs)
	}

	checker.allowed = true
	req = httptest.NewRequest(http.MethodGet, "/admin/authz/casbin-rules", nil)
	req.Header.Set("Authorization", "Bearer "+mintToken(t, key, kid, userID.String()))
	req = req.WithContext(metadata.NewOutgoingContext(req.Context(), metadata.Pairs(
		httpmeta.UserIDKey, uuid.NewString(),
		httpmeta.UserIDKey, uuid.NewString(),
	)))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("authorized platform user = %d body=%s, want 200", rec.Code, rec.Body.String())
	}
	if checker.gotUserID != userID || checker.gotPermission != authzmodel.PlatformPermissionPolicyRead {
		t.Fatalf("platform check = (%v, %q), want (%v, %q)", checker.gotUserID, checker.gotPermission, userID, authzmodel.PlatformPermissionPolicyRead)
	}
	if len(checker.gotMetadataIDs) != 0 {
		t.Fatalf("platform authorization transport carried delegated identities %v", checker.gotMetadataIDs)
	}
}

func TestAdminForwardsIdentity(t *testing.T) {
	t.Parallel()

	authz := &fakeAuthzAdmin{}
	sub := uuid.NewString()
	h, key, kid := buildHandler(t, authz, &fakePlatformChecker{allowed: true})
	token := mintToken(t, key, kid, sub)

	req := httptest.NewRequest(http.MethodGet, "/admin/authz/casbin-rules?domain=*", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("admin with token = %d body=%s", rec.Code, rec.Body.String())
	}
	if len(authz.gotUserIDs) != 1 || authz.gotUserIDs[0] != sub {
		t.Fatalf("authz received x-user-id values %v, want [%q]", authz.gotUserIDs, sub)
	}
}

func TestAdminAuthorizationUnavailableFailsClosed(t *testing.T) {
	t.Parallel()

	h, key, kid := buildHandler(t, &fakeAuthzAdmin{}, &fakePlatformChecker{err: errors.New("authz down")})
	req := httptest.NewRequest(http.MethodGet, "/admin/authz/casbin-rules", nil)
	req.Header.Set("Authorization", "Bearer "+mintToken(t, key, kid, uuid.NewString()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("admin with unavailable authorization = %d, want 503", rec.Code)
	}
}

func TestCurrentAdminAuthenticationOutcomes(t *testing.T) {
	t.Parallel()

	authz := &fakeAuthzAdmin{}
	adminUserID := uuid.NewString()
	h, key, kid := buildHandler(t, authz, &fakePlatformChecker{allowed: true})
	path := "/admin/authz/casbin-rules"

	tests := []struct {
		name       string
		token      string
		wantStatus int
	}{
		{
			name:       "missing token",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "invalid token",
			token:      "not-a-jwt",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "expired token",
			token: mintTokenWithExpiration(
				t,
				key,
				kid,
				adminUserID,
				time.Now().Add(-time.Minute),
			),
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "valid platform-authorized token",
			token:      mintToken(t, key, kid, adminUserID),
			wantStatus: http.StatusOK,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			if tc.token != "" {
				req.Header.Set("Authorization", "Bearer "+tc.token)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d body=%s, want %d", rec.Code, rec.Body.String(), tc.wantStatus)
			}
		})
	}

	if len(authz.gotUserIDs) != 1 || authz.gotUserIDs[0] != adminUserID {
		t.Fatalf("authorized JWT subject forwarded as %v, want [%q]", authz.gotUserIDs, adminUserID)
	}
}

func TestAdminRoutePermissionMapping(t *testing.T) {
	t.Parallel()

	tests := []struct {
		method     string
		path       string
		permission string
	}{
		{http.MethodGet, "/admin/authz/casbin-rules", authzmodel.PlatformPermissionPolicyRead},
		{http.MethodPost, "/admin/authz/reload-policy", authzmodel.PlatformPermissionPolicyReload},
		{http.MethodGet, "/admin/oidc/clients", authzmodel.PlatformPermissionOIDCClientRead},
	}
	for _, test := range tests {
		permission, ok := adminRoutePermission(test.method, test.path)
		if !ok || permission != test.permission {
			t.Errorf("permission for %s %s = (%q, %v), want (%q, true)", test.method, test.path, permission, ok, test.permission)
		}
	}
	if _, ok := adminRoutePermission(http.MethodPost, "/admin/future"); ok {
		t.Fatal("unknown admin route was assigned a permission")
	}
}

func TestUnknownAdminRouteFailsClosed(t *testing.T) {
	t.Parallel()

	h, key, kid := buildHandler(t, &fakeAuthzAdmin{}, &fakePlatformChecker{allowed: true})
	req := httptest.NewRequest(http.MethodPost, "/admin/future", nil)
	req.Header.Set("Authorization", "Bearer "+mintToken(t, key, kid, uuid.NewString()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("unknown admin route = %d, want 403", rec.Code)
	}
}
