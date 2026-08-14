package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	authnpb "sanzi.io/muid/api/proto/authn/v1"
	basicpb "sanzi.io/muid/api/proto/authn/v1/basic"
	challengepb "sanzi.io/muid/api/proto/authn/v1/challenge"
	sessionpb "sanzi.io/muid/api/proto/authn/v1/session"
	"sanzi.io/muid/infra/geoip"
	"sanzi.io/muid/infra/mocked"
	"sanzi.io/muid/infra/turnstile"
	"sanzi.io/muid/pkg/gateway/csrf"
	"sanzi.io/muid/pkg/shared/kv"
)

const (
	testSessionToken  = "sess-token-123"
	defaultCookieName = "__Host-muid_session"
)

// fakeAuthnFlow implements the auth-flow + session-lifecycle RPCs the GraphQL
// resolvers use.
type fakeAuthnFlow struct {
	authnpb.AuthenticationFlowServiceClient
	authnpb.SessionServiceClient
	authnpb.LinkedIdentityServiceClient
	continueErr    error
	rotatedTok     string // session token returned by RefreshSession
	issueAccessErr error
}

func (fakeAuthnFlow) StartLogin(_ context.Context, _ *authnpb.StartLoginRequest, _ ...grpc.CallOption) (*authnpb.StartLoginResponse, error) {
	ec := &challengepb.EmailChallenge{}
	ec.SetEmailMasked("a***@test")
	ec.SetResendCooldownMillis(60000)
	ch := &challengepb.AuthChallenge{}
	ch.SetChallengeId(uuid.NewString())
	ch.SetEmailChallenge(ec)
	resp := &authnpb.StartLoginResponse{}
	resp.SetTransitionId(uuid.NewString())
	resp.SetChallenge(ch)
	return resp, nil
}

func (f fakeAuthnFlow) ContinueLogin(_ context.Context, _ *authnpb.ContinueLoginRequest, _ ...grpc.CallOption) (*authnpb.ContinueLoginResponse, error) {
	if f.continueErr != nil {
		return nil, f.continueErr
	}
	tok := &sessionpb.SessionToken{}
	tok.SetValue(testSessionToken)
	sctx := &sessionpb.SessionContext{}
	sctx.SetSessionToken(tok)
	result := &sessionpb.AuthenticatedResult{}
	result.SetUserId(uuid.NewString())
	result.SetAuthLevel(sessionpb.AuthLevel_AUTH_LEVEL_HIGH)
	result.SetSessionContext(sctx)
	success := &sessionpb.AuthSuccess{}
	success.SetResult(result)
	resp := &authnpb.ContinueLoginResponse{}
	resp.SetStatus(basicpb.AuthStatus_AUTH_STATUS_AUTHENTICATED)
	resp.SetAuthSuccess(success)
	return resp, nil
}

func (f fakeAuthnFlow) RefreshSession(_ context.Context, _ *authnpb.RefreshSessionRequest, _ ...grpc.CallOption) (*authnpb.RefreshSessionResponse, error) {
	tok := &sessionpb.SessionToken{}
	tok.SetValue(f.rotatedTok)
	sctx := &sessionpb.SessionContext{}
	sctx.SetSessionToken(tok)
	resp := &authnpb.RefreshSessionResponse{}
	resp.SetSessionContext(sctx)
	return resp, nil
}

func (fakeAuthnFlow) RevokeSession(_ context.Context, _ *authnpb.RevokeSessionRequest, _ ...grpc.CallOption) (*authnpb.RevokeSessionResponse, error) {
	resp := &authnpb.RevokeSessionResponse{}
	resp.SetSuccess(true)
	return resp, nil
}

func (f fakeAuthnFlow) IssueAccessToken(ctx context.Context, _ *authnpb.IssueAccessTokenRequest, _ ...grpc.CallOption) (*authnpb.IssueAccessTokenResponse, error) {
	if f.issueAccessErr != nil {
		return nil, f.issueAccessErr
	}
	at := &sessionpb.AccessToken{}
	at.SetValue("minted-jwt")
	at.SetExpiresAt(timestamppb.New(time.Now().Add(5 * time.Minute)))
	resp := &authnpb.IssueAccessTokenResponse{}
	resp.SetAccessToken(at)
	return resp, nil
}

func (fakeAuthnFlow) GetSessionPrincipal(
	_ context.Context,
	_ *authnpb.GetSessionPrincipalRequest,
	_ ...grpc.CallOption,
) (*authnpb.GetSessionPrincipalResponse, error) {
	principal := &authnpb.SessionPrincipal{}
	principal.SetUserId("550e8400-e29b-41d4-a716-446655440000")
	principal.SetAuthLevel(sessionpb.AuthLevel_AUTH_LEVEL_HIGH)
	principal.SetIssuedAt(timestamppb.New(time.Now().Add(-time.Minute)))
	principal.SetExpiresAt(timestamppb.New(time.Now().Add(time.Hour)))
	resp := &authnpb.GetSessionPrincipalResponse{}
	resp.SetValid(true)
	resp.SetPrincipal(principal)
	return resp, nil
}

type gatewayAuthnClient interface {
	authnpb.AuthenticationFlowServiceClient
	authnpb.SessionServiceClient
	authnpb.LinkedIdentityServiceClient
}

func authFailureErr(reason string) error {
	af := &sessionpb.AuthFailure{}
	af.SetReason(reason)
	af.SetErrorCode(sessionpb.AuthErrorCode_AUTH_ERROR_CODE_AUTHENTICATION_FAILED)
	st, err := status.New(codes.Unauthenticated, "auth failed").WithDetails(af)
	if err != nil {
		return status.Error(codes.Unauthenticated, "auth failed")
	}
	return st.Err()
}

func gqlInfra(authn gatewayAuthnClient, verifier turnstile.Verifier, csrfMgr *csrf.Manager, store kv.AtomicKVStore) *InfraDependencies {
	return &InfraDependencies{
		// Debug enables ad-hoc queries so these tests can post operations
		// directly without a persisted-operations manifest.
		GlobalConfig:         Config{Debug: true, Port: 8080, RateLimit: 100, RateLimitWindowSeconds: 60, RiskBlockThreshold: 90, RiskPoWThreshold: 50, PoWDifficulty: 8},
		Redis:                store,
		Geo:                  geoip.NewMockResolver(geoip.GeoInfo{CountryCode: "US", Resolved: true}),
		Turnstile:            verifier,
		CSRF:                 csrfMgr,
		OIDCClient:           fakeOIDC{},
		AuthFlowClient:       authn,
		SessionClient:        authn,
		LinkedIdentityClient: authn,
	}
}

// postGraphQL posts a raw GraphQL operation and returns the recorder + decoded body.
func postGraphQL(t *testing.T, h http.Handler, query, csrfToken string, cookies ...*http.Cookie) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"query": query})
	req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	if csrfToken != "" {
		req.Header.Set("X-CSRF-Token", csrfToken)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("graphql status = %d body=%s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v body=%s", err, rec.Body.String())
	}
	return rec, out
}

func sessionCookie(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func TestStartAuthSuccess(t *testing.T) {
	t.Parallel()

	h := newHandler(gqlInfra(fakeAuthnFlow{}, turnstile.AlwaysValid(), nil, mocked.NewMockKVStore()))
	_, out := postGraphQL(t, h, `mutation { startAuth(input:{method:EMAIL_OTP, identifier:"a@test", captchaToken:"tok"}) { transitionId challenge { challengeId detail { __typename ... on EmailChallenge { emailMasked resendCooldownMillis } } } } }`, "")
	data, _ := out["data"].(map[string]any)
	sa, _ := data["startAuth"].(map[string]any)
	if sa["transitionId"] == nil || sa["transitionId"] == "" {
		t.Fatalf("missing transitionId: %v", out)
	}
	ch, _ := sa["challenge"].(map[string]any)
	detail, _ := ch["detail"].(map[string]any)
	if detail["__typename"] != "EmailChallenge" || detail["emailMasked"] != "a***@test" {
		t.Fatalf("unexpected challenge detail = %v (full %v)", detail, out)
	}
}

func TestStartAuthRequiresCaptcha(t *testing.T) {
	t.Parallel()

	// Even with a permissive verifier, a missing captcha token is rejected: the
	// CAPTCHA gate is mandatory, not opt-in by the client.
	h := newHandler(gqlInfra(fakeAuthnFlow{}, turnstile.AlwaysValid(), nil, mocked.NewMockKVStore()))
	_, out := postGraphQL(t, h, `mutation { startAuth(input:{method:EMAIL_OTP, identifier:"a@test"}) { transitionId } }`, "")
	if _, ok := out["errors"]; !ok {
		t.Fatalf("missing captcha token should be rejected, got %v", out)
	}
}

func TestStartAuthCaptchaFails(t *testing.T) {
	t.Parallel()

	h := newHandler(gqlInfra(fakeAuthnFlow{}, turnstile.AlwaysInvalid(), nil, mocked.NewMockKVStore()))
	_, out := postGraphQL(t, h, `mutation { startAuth(input:{method:EMAIL_OTP, identifier:"a@test", captchaToken:"bad"}) { transitionId } }`, "")
	if _, ok := out["errors"]; !ok {
		t.Fatalf("expected captcha error, got %v", out)
	}
}

func TestContinueAuthSuccessSetsCookie(t *testing.T) {
	t.Parallel()

	h := newHandler(gqlInfra(fakeAuthnFlow{}, turnstile.AlwaysValid(), nil, mocked.NewMockKVStore()))
	rec, out := postGraphQL(t, h, `mutation { continueAuth(input:{transitionId:"`+uuid.NewString()+`", proof:{email:{otpCode:"123456"}}}) { status session { userId authLevel } } }`, "")
	data, _ := out["data"].(map[string]any)
	ca, _ := data["continueAuth"].(map[string]any)
	if ca["status"] != "AUTHENTICATED" {
		t.Fatalf("status = %v (full %v)", ca["status"], out)
	}
	sess, _ := ca["session"].(map[string]any)
	if sess["userId"] == nil || sess["userId"] == "" {
		t.Fatalf("missing userId: %v", out)
	}
	// The opaque session token must NOT appear in the body — only in the cookie.
	if strings.Contains(rec.Body.String(), testSessionToken) {
		t.Fatalf("session token leaked into response body: %s", rec.Body.String())
	}
	c := sessionCookie(rec, defaultCookieName)
	if c == nil || c.Value != testSessionToken {
		t.Fatalf("session cookie not set correctly: %+v", c)
	}
	if !c.HttpOnly {
		t.Fatalf("session cookie must be HttpOnly")
	}
}

func TestContinueAuthFailureIsRecorded(t *testing.T) {
	t.Parallel()

	store := mocked.NewMockKVStore()
	authn := fakeAuthnFlow{continueErr: authFailureErr("invalid code")}
	h := newHandler(gqlInfra(authn, turnstile.AlwaysValid(), nil, store))

	_, out := postGraphQL(t, h, `mutation { continueAuth(input:{transitionId:"`+uuid.NewString()+`", proof:{email:{otpCode:"000000"}}}) { status } }`, "")
	errs, ok := out["errors"].([]any)
	if !ok || len(errs) == 0 {
		t.Fatalf("expected a GraphQL error, got %v", out)
	}
	// The structured AuthErrorCode is surfaced as the error extension "code".
	first, _ := errs[0].(map[string]any)
	ext, _ := first["extensions"].(map[string]any)
	if ext["code"] != "AUTHENTICATION_FAILED" {
		t.Fatalf("expected error code extension, got %v", first)
	}
	// httptest default RemoteAddr is 192.0.2.1; the resolver records a failure.
	if v, err := store.Get(context.Background(), "muid:risk:fail:192.0.2.1"); err != nil || string(v) != "1" {
		t.Fatalf("expected recorded auth failure (got %q, err %v)", v, err)
	}
}

func TestContinueAuthRejectsMultipleProofs(t *testing.T) {
	t.Parallel()

	h := newHandler(gqlInfra(fakeAuthnFlow{}, turnstile.AlwaysValid(), nil, mocked.NewMockKVStore()))
	_, out := postGraphQL(t, h, `mutation { continueAuth(input:{transitionId:"`+uuid.NewString()+`", proof:{email:{otpCode:"123456"}, oauth:{code:"c", state:"s"}}}) { status } }`, "")
	if _, ok := out["errors"]; !ok {
		t.Fatalf("expected validation error for multiple proofs, got %v", out)
	}
}

func TestRefreshSessionRotatesCookie(t *testing.T) {
	t.Parallel()

	const rotated = "rotated-token-456"
	h := newHandler(gqlInfra(fakeAuthnFlow{rotatedTok: rotated}, turnstile.AlwaysValid(), nil, mocked.NewMockKVStore()))
	cur := &http.Cookie{Name: defaultCookieName, Value: testSessionToken}
	rec, out := postGraphQL(t, h, `mutation { refreshSession { expiresAt } }`, "", cur)
	if _, ok := out["errors"]; ok {
		t.Fatalf("refreshSession failed: %v", out)
	}
	c := sessionCookie(rec, defaultCookieName)
	if c == nil || c.Value != rotated {
		t.Fatalf("expected rotated session cookie, got %+v", c)
	}
}

func TestRefreshSessionRequiresCookie(t *testing.T) {
	t.Parallel()

	h := newHandler(gqlInfra(fakeAuthnFlow{}, turnstile.AlwaysValid(), nil, mocked.NewMockKVStore()))
	_, out := postGraphQL(t, h, `mutation { refreshSession { expiresAt } }`, "")
	if _, ok := out["errors"]; !ok {
		t.Fatalf("expected authentication required error, got %v", out)
	}
}

func TestLogoutClearsCookie(t *testing.T) {
	t.Parallel()

	h := newHandler(gqlInfra(fakeAuthnFlow{}, turnstile.AlwaysValid(), nil, mocked.NewMockKVStore()))
	cur := &http.Cookie{Name: defaultCookieName, Value: testSessionToken}
	rec, out := postGraphQL(t, h, `mutation { logout }`, "", cur)
	data, _ := out["data"].(map[string]any)
	if data["logout"] != true {
		t.Fatalf("logout = %v (full %v)", data["logout"], out)
	}
	c := sessionCookie(rec, defaultCookieName)
	if c == nil || c.MaxAge >= 0 || c.Value != "" {
		t.Fatalf("logout should expire the cookie, got %+v", c)
	}
}

func TestViewerSessionUnauthenticatedIsNull(t *testing.T) {
	t.Parallel()

	h := newHandler(gqlInfra(fakeAuthnFlow{}, turnstile.AlwaysValid(), nil, mocked.NewMockKVStore()))
	_, out := postGraphQL(t, h, `query { viewerSession { userId } }`, "")
	if _, ok := out["errors"]; ok {
		t.Fatalf("viewerSession should not error when unauthenticated: %v", out)
	}
	data, _ := out["data"].(map[string]any)
	if data["viewerSession"] != nil {
		t.Fatalf("expected null viewerSession, got %v", data["viewerSession"])
	}
}

func TestViewerSessionUsesCredentialFreePrincipal(t *testing.T) {
	t.Parallel()

	h := newHandler(gqlInfra(fakeAuthnFlow{}, turnstile.AlwaysValid(), nil, mocked.NewMockKVStore()))
	cur := &http.Cookie{Name: defaultCookieName, Value: testSessionToken}
	_, out := postGraphQL(t, h, `query { viewerSession { userId authLevel expiresAt } }`, "", cur)
	if _, ok := out["errors"]; ok {
		t.Fatalf("viewerSession failed: %v", out)
	}
	data, _ := out["data"].(map[string]any)
	viewer, _ := data["viewerSession"].(map[string]any)
	if viewer["userId"] != "550e8400-e29b-41d4-a716-446655440000" {
		t.Fatalf("viewerSession userId = %v", viewer["userId"])
	}
	if viewer["authLevel"] != "HIGH" || viewer["expiresAt"] == nil {
		t.Fatalf("viewerSession principal mapping = %v", viewer)
	}
}

func TestGraphQLCSRFEnforced(t *testing.T) {
	t.Parallel()

	csrfMgr, err := csrf.New([]byte("secret"), 0)
	if err != nil {
		t.Fatalf("csrf: %v", err)
	}
	h := newHandler(gqlInfra(fakeAuthnFlow{}, turnstile.AlwaysValid(), csrfMgr, mocked.NewMockKVStore()))

	// Without a CSRF token the mutation is rejected at the middleware.
	body, _ := json.Marshal(map[string]any{"query": `mutation { startAuth(input:{method:EMAIL_OTP, identifier:"a@test", captchaToken:"tok"}) { transitionId } }`})
	req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF token should be 403, got %d", rec.Code)
	}

	// With a valid token it passes.
	token, _ := csrfMgr.Generate()
	_, out := postGraphQL(t, h, `mutation { startAuth(input:{method:EMAIL_OTP, identifier:"a@test", captchaToken:"tok"}) { transitionId } }`, token)
	if _, ok := out["errors"]; ok {
		t.Fatalf("valid CSRF request should succeed, got %v", out)
	}
}
