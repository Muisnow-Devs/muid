package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	authzpb "sanzi.io/muid/api/proto/authz/v1"
	profilepb "sanzi.io/muid/api/proto/profile/v1"
	"sanzi.io/muid/infra/geoip"
	"sanzi.io/muid/infra/mocked"
	"sanzi.io/muid/infra/turnstile"
	"sanzi.io/muid/pkg/gateway/jwtauth"
)

// mdUserID reads the gateway-injected caller id from the outgoing gRPC metadata.
func mdUserID(ctx context.Context) string {
	md, ok := metadata.FromOutgoingContext(ctx)
	if !ok {
		return ""
	}
	if v := md.Get("x-user-id"); len(v) > 0 {
		return v[0]
	}
	return ""
}

type fakeVerifier struct {
	userID uuid.UUID
	err    error
}

func (f fakeVerifier) Verify(_ context.Context, _ string) (jwtauth.Claims, error) {
	if f.err != nil {
		return jwtauth.Claims{}, f.err
	}
	return jwtauth.Claims{UserID: f.userID, ExpiresAt: time.Now().Add(5 * time.Minute)}, nil
}

type fakeAuthzUser struct {
	authzpb.AuthzUserServiceClient
	gotUserID string
	createErr error
	orgID     string
	orgs      []*authzpb.OrganizationMembershipView
	perms     []string
}

func (f *fakeAuthzUser) CreateMyOrganization(ctx context.Context, _ *authzpb.CreateMyOrganizationRequest, _ ...grpc.CallOption) (*authzpb.CreateMyOrganizationResponse, error) {
	f.gotUserID = mdUserID(ctx)
	if f.createErr != nil {
		return nil, f.createErr
	}
	resp := &authzpb.CreateMyOrganizationResponse{}
	resp.SetOrganizationId(f.orgID)
	return resp, nil
}

func (f *fakeAuthzUser) ListMyOrganizations(ctx context.Context, _ *authzpb.ListMyOrganizationsRequest, _ ...grpc.CallOption) (*authzpb.ListMyOrganizationsResponse, error) {
	f.gotUserID = mdUserID(ctx)
	resp := &authzpb.ListMyOrganizationsResponse{}
	resp.SetOrganizations(f.orgs)
	return resp, nil
}

func (f *fakeAuthzUser) ListMyPermissions(ctx context.Context, _ *authzpb.ListMyPermissionsRequest, _ ...grpc.CallOption) (*authzpb.ListMyPermissionsResponse, error) {
	f.gotUserID = mdUserID(ctx)
	resp := &authzpb.ListMyPermissionsResponse{}
	resp.SetPermissions(f.perms)
	return resp, nil
}

type fakeAuthzOrg struct {
	authzpb.AuthzOrganizationAdminServiceClient
	gotUserID string
	listErr   error
	members   []*authzpb.MemberView
}

func (f *fakeAuthzOrg) ListMembers(ctx context.Context, _ *authzpb.ListMembersRequest, _ ...grpc.CallOption) (*authzpb.ListMembersResponse, error) {
	f.gotUserID = mdUserID(ctx)
	if f.listErr != nil {
		return nil, f.listErr
	}
	resp := &authzpb.ListMembersResponse{}
	resp.SetMembers(f.members)
	return resp, nil
}

type fakeProfile struct {
	profilepb.ProfileServiceClient
	getCalls  int32
	gotUserID string
	updateErr error
}

func (f *fakeProfile) GetProfile(_ context.Context, req *profilepb.GetProfileRequest, _ ...grpc.CallOption) (*profilepb.GetProfileResponse, error) {
	atomic.AddInt32(&f.getCalls, 1)
	resp := &profilepb.GetProfileResponse{}
	resp.SetId(req.GetId())
	resp.SetUsername("user_" + req.GetId()[:4])
	resp.SetDisplayName("User " + req.GetId()[:4])
	return resp, nil
}

func (f *fakeProfile) UpdateProfile(ctx context.Context, req *profilepb.UpdateProfileRequest, _ ...grpc.CallOption) (*profilepb.UpdateProfileResponse, error) {
	f.gotUserID = mdUserID(ctx)
	if f.updateErr != nil {
		return nil, f.updateErr
	}
	// record the mask onto the fake via the request for assertions
	lastUpdateMask = req.GetUpdateMask().GetPaths()
	resp := &profilepb.UpdateProfileResponse{}
	resp.SetId(mdUserID(ctx))
	return resp, nil
}

var lastUpdateMask []string

func dataInfra(t *testing.T, verifier *fakeVerifier, authzUser *fakeAuthzUser, authzOrg *fakeAuthzOrg, profile *fakeProfile) *InfraDependencies {
	t.Helper()
	return &InfraDependencies{
		GlobalConfig:     Config{Debug: true, Port: 8080, RateLimit: 1000, RateLimitWindowSeconds: 60, RiskBlockThreshold: 90, RiskPoWThreshold: 50, PoWDifficulty: 8, AccessTokenCookieName: "__Secure-muid_at"},
		Redis:            mocked.NewMockKVStore(),
		Geo:              geoip.NewMockResolver(geoip.GeoInfo{CountryCode: "US", Resolved: true}),
		Turnstile:        turnstile.AlwaysValid(),
		OIDCClient:       fakeOIDC{},
		AuthnClient:      fakeAuthnFlow{},
		AuthzUserClient:  authzUser,
		AuthzOrgClient:   authzOrg,
		ProfileClient:    profile,
		OrgProfileClient: nil,
		Verifier:         verifier,
	}
}

const atCookieName = "__Secure-muid_at"

func TestViewerComposesAndInjectsUserID(t *testing.T) {
	t.Parallel()

	uid := uuid.New()
	memberID := uuid.New().String()
	mv := &authzpb.MemberView{}
	mv.SetUserId(memberID)
	mv.SetRole("member")
	org := &authzpb.OrganizationMembershipView{}
	org.SetOrganizationId(uuid.New().String())
	org.SetName("Acme")
	org.SetRole("owner")

	authzUser := &fakeAuthzUser{orgs: []*authzpb.OrganizationMembershipView{org}}
	authzOrg := &fakeAuthzOrg{members: []*authzpb.MemberView{mv}}
	profile := &fakeProfile{}
	h := newHandler(dataInfra(t, &fakeVerifier{userID: uid}, authzUser, authzOrg, profile))

	q := `query { viewer { profile { id username } organizations { name role organization { members { members { userId profile { id } } } } } } }`
	_, out := postGraphQL(t, h, q, "", &http.Cookie{Name: atCookieName, Value: "any"})
	if errs, ok := out["errors"]; ok {
		t.Fatalf("viewer query errored: %v", errs)
	}
	data, _ := out["data"].(map[string]any)
	viewer, _ := data["viewer"].(map[string]any)
	prof, _ := viewer["profile"].(map[string]any)
	if prof["id"] != uid.String() {
		t.Fatalf("viewer.profile.id = %v, want %v", prof["id"], uid)
	}
	// The verified caller id was injected as x-user-id on the authz call.
	if authzUser.gotUserID != uid.String() {
		t.Fatalf("authz did not receive x-user-id: got %q want %q", authzUser.gotUserID, uid)
	}
	if authzOrg.gotUserID != uid.String() {
		t.Fatalf("authz org did not receive x-user-id: got %q", authzOrg.gotUserID)
	}
}

func TestDataPlaneRequiresAuthentication(t *testing.T) {
	t.Parallel()

	h := newHandler(dataInfra(t, &fakeVerifier{userID: uuid.New()}, &fakeAuthzUser{}, &fakeAuthzOrg{}, &fakeProfile{}))
	// No cookies at all → unauthenticated. viewer returns null (probe).
	_, out := postGraphQL(t, h, `query { viewer { profile { id } } }`, "")
	data, _ := out["data"].(map[string]any)
	if data["viewer"] != nil {
		t.Fatalf("expected null viewer when unauthenticated, got %v", data["viewer"])
	}
	// A mutation that requires auth must error.
	_, out = postGraphQL(t, h, `mutation { createMyOrganization(input:{name:"X"}) { id } }`, "")
	if _, ok := out["errors"]; !ok {
		t.Fatalf("expected authentication error, got %v", out)
	}
}

func TestDataPlaneMintsAccessTokenFromSessionCookie(t *testing.T) {
	t.Parallel()

	uid := uuid.New()
	authzUser := &fakeAuthzUser{orgID: uuid.New().String()}
	h := newHandler(dataInfra(t, &fakeVerifier{userID: uid}, authzUser, &fakeAuthzOrg{}, &fakeProfile{}))

	// Only the session cookie is present (no AT cookie) → gateway mints one.
	rec, out := postGraphQL(t, h, `mutation { createMyOrganization(input:{name:"Acme"}) { id } }`, "",
		&http.Cookie{Name: defaultCookieName, Value: testSessionToken})
	if errs, ok := out["errors"]; ok {
		t.Fatalf("createMyOrganization errored: %v", errs)
	}
	if authzUser.gotUserID != uid.String() {
		t.Fatalf("x-user-id not injected after mint: got %q", authzUser.gotUserID)
	}
	// The freshly minted access token was set as the subdomain-scoped cookie.
	if c := sessionCookie(rec, atCookieName); c == nil || c.Value != "minted-jwt" || !c.HttpOnly {
		t.Fatalf("expected minted access-token cookie, got %+v", c)
	}
}

func TestUpdateProfileBuildsMaskFromNonNullFields(t *testing.T) {
	t.Parallel()

	uid := uuid.New()
	profile := &fakeProfile{}
	h := newHandler(dataInfra(t, &fakeVerifier{userID: uid}, &fakeAuthzUser{}, &fakeAuthzOrg{}, profile))

	lastUpdateMask = nil
	_, out := postGraphQL(t, h, `mutation { updateProfile(input:{displayName:"New Name", bio:"hi"}) { id } }`, "",
		&http.Cookie{Name: atCookieName, Value: "any"})
	if errs, ok := out["errors"]; ok {
		t.Fatalf("updateProfile errored: %v", errs)
	}
	// displayName maps to identity.name; bio to identity.bio; username/locale/timezone omitted.
	want := map[string]bool{"identity.name": true, "identity.bio": true}
	if len(lastUpdateMask) != 2 {
		t.Fatalf("update mask = %v, want 2 paths", lastUpdateMask)
	}
	for _, p := range lastUpdateMask {
		if !want[p] {
			t.Fatalf("unexpected mask path %q (mask %v)", p, lastUpdateMask)
		}
	}
	if profile.gotUserID != uid.String() {
		t.Fatalf("profile did not receive x-user-id: got %q", profile.gotUserID)
	}
}

func TestForbiddenMapsToClientSafeError(t *testing.T) {
	t.Parallel()

	uid := uuid.New()
	authzUser := &fakeAuthzUser{createErr: status.Error(codes.PermissionDenied, "casbin: denied")}
	h := newHandler(dataInfra(t, &fakeVerifier{userID: uid}, authzUser, &fakeAuthzOrg{}, &fakeProfile{}))

	_, out := postGraphQL(t, h, `mutation { createMyOrganization(input:{name:"X"}) { id } }`, "",
		&http.Cookie{Name: atCookieName, Value: "any"})
	errs, ok := out["errors"].([]any)
	if !ok || len(errs) == 0 {
		t.Fatalf("expected error, got %v", out)
	}
	first, _ := errs[0].(map[string]any)
	if first["message"] != "forbidden" {
		t.Fatalf("expected client-safe 'forbidden', got %v", first["message"])
	}
}

func TestAccessTokenEndpointMintsCookie(t *testing.T) {
	t.Parallel()

	uid := uuid.New()
	h := newHandler(dataInfra(t, &fakeVerifier{userID: uid}, &fakeAuthzUser{}, &fakeAuthzOrg{}, &fakeProfile{}))

	// Without a session cookie → 401.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/security/access-token", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no session cookie should be 401, got %d", rec.Code)
	}

	// With a session cookie → mints + sets the access-token cookie. The response
	// is status-only (no body); the JWT lives in the httpOnly cookie.
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/security/access-token", nil)
	req.AddCookie(&http.Cookie{Name: defaultCookieName, Value: testSessionToken})
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("access-token mint should be 204, got %d body=%s", rec.Code, rec.Body.String())
	}
	if c := sessionCookie(rec, atCookieName); c == nil || c.Value != "minted-jwt" || !c.HttpOnly {
		t.Fatalf("expected minted access-token cookie, got %+v", c)
	}
	// The response body must be empty (status-code only).
	if body := strings.TrimSpace(rec.Body.String()); body != "" {
		t.Fatalf("access-token response should have no body, got %q", body)
	}
}

func TestAccessTokenEndpointRejectsDisallowedOrigin(t *testing.T) {
	t.Parallel()

	infra := dataInfra(t, &fakeVerifier{userID: uuid.New()}, &fakeAuthzUser{}, &fakeAuthzOrg{}, &fakeProfile{})
	infra.GlobalConfig.CORSAllowedOrigins = []string{"https://app.muid.io"}
	h := newHandler(infra)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/security/access-token", nil)
	req.Header.Set("Origin", "https://evil.example")
	req.AddCookie(&http.Cookie{Name: defaultCookieName, Value: testSessionToken})
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("disallowed origin should be 403, got %d", rec.Code)
	}

	// An allowed origin passes through and mints.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/security/access-token", nil)
	req.Header.Set("Origin", "https://app.muid.io")
	req.AddCookie(&http.Cookie{Name: defaultCookieName, Value: testSessionToken})
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("allowed origin should mint (204), got %d", rec.Code)
	}
}
