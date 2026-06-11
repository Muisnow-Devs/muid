package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"

	"sanzi.io/muid/infra/mocked"
	gcpsecretmanager "sanzi.io/muid/infra/secretmanager"
	"sanzi.io/muid/internal/authn/ent"
	"sanzi.io/muid/internal/authn/ent/enttest"
	"sanzi.io/muid/internal/authn/ent/oidcclient"
	"sanzi.io/muid/internal/authn/ent/oidcrefreshtoken"
	"sanzi.io/muid/internal/authn/oidc/policy"
	"sanzi.io/muid/internal/authn/oidc/store"
	"sanzi.io/muid/internal/oidctoken"
	"sanzi.io/muid/internal/signature"
)

type stubMembership bool

func (s stubMembership) IsMember(context.Context, uuid.UUID, uuid.UUID) (bool, error) {
	return bool(s), nil
}

type providerFixture struct {
	provider *Provider
	db       *ent.Client
	verifier *oidctoken.Verifier
	userID   uuid.UUID
	client   *ent.OIDCClient
}

func newProviderFixture(t *testing.T, dbName string) (context.Context, providerFixture) {
	t.Helper()
	ctx := context.Background()

	db := enttest.Open(t, "sqlite3", "file:"+dbName+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() { db.Close() })

	manager, err := signature.NewSignatureManager(
		gcpsecretmanager.NewFakeSecretManager("test-project"),
		signature.ManagerConfig{SecretName: "oidc-signing-key"},
	)
	if err != nil {
		t.Fatalf("NewSignatureManager: %v", err)
	}
	_, err = manager.RotateSecret(ctx)
	if err != nil {
		t.Fatalf("RotateSecret: %v", err)
	}

	kvStore := mocked.NewMockKVStore()
	signer := oidctoken.NewSigner(manager, "https://id.test")
	verifier := oidctoken.NewVerifier(manager, "https://id.test")
	evaluator := policy.NewEvaluator(stubMembership(true), policy.EntAllowlist{DB: db})

	provider := NewProvider(
		db,
		store.NewKVCodeStore(kvStore),
		store.NewKVPendingStore(kvStore),
		store.NewKVDeviceStore(kvStore),
		evaluator,
		signer,
		verifier,
		nil,
		Config{
			Issuer:                "https://id.test",
			AccessTokenTTL:        time.Hour,
			DeviceVerificationURI: "https://id.test/device",
			DevicePollInterval:    time.Millisecond,
		},
	)

	userID := uuid.New()
	err = db.UserRef.Create().SetID(userID).Exec(ctx)
	if err != nil {
		t.Fatalf("create user ref: %v", err)
	}

	client, err := db.OIDCClient.Create().
		SetClientID("client-abc").
		SetClientName("Test App").
		SetOwnerOrganizationID(uuid.New()).
		SetScopes([]string{ScopeOpenID, ScopeProfile, ScopeEmail}).
		SetGrantTypes([]string{
			policy.GrantTypeAuthorizationCode,
			policy.GrantTypeRefreshToken,
			policy.GrantTypeDeviceCode,
		}).
		SetTokenEndpointAuthMethod(oidcclient.TokenEndpointAuthMethodNone).
		SetAccessPolicy(oidcclient.AccessPolicyPublic).
		SetPublishStatus(oidcclient.PublishStatusPublished).
		Save(ctx)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	err = db.OIDCCallbackURI.Create().
		SetClientRefID(client.ID).
		SetURI("https://app.test/cb").
		Exec(ctx)
	if err != nil {
		t.Fatalf("create callback uri: %v", err)
	}

	return ctx, providerFixture{
		provider: provider,
		db:       db,
		verifier: verifier,
		userID:   userID,
		client:   client,
	}
}

func pkcePair() (verifier, challenge string) {
	verifier = "test-verifier-test-verifier-test-verifier-43c"
	digest := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(digest[:])
}

func authorizeInput(challenge string) AuthorizeInput {
	return AuthorizeInput{
		ClientID:            "client-abc",
		RedirectURI:         "https://app.test/cb",
		ResponseType:        "code",
		Scopes:              []string{ScopeOpenID, ScopeEmail},
		State:               "state-1",
		Nonce:               "nonce-1",
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
	}
}

func wantOAuthCode(t *testing.T, err error, wantCode string) {
	t.Helper()
	oauthErr, ok := AsOAuthError(err)
	if !ok {
		t.Fatalf("err = %v, want OAuthError %q", err, wantCode)
	}
	if oauthErr.Code != wantCode {
		t.Fatalf("oauth error = %q (%s), want %q", oauthErr.Code, oauthErr.Description, wantCode)
	}
}

func TestAuthorizationCodeFlow(t *testing.T) {
	t.Parallel()

	ctx, fx := newProviderFixture(t, "oidccodeflow")
	user := &SessionUser{UserID: fx.userID, SessionID: uuid.New(), AuthTime: time.Now()}
	verifier, challenge := pkcePair()

	// Anonymous: login required.
	result, err := fx.provider.Authorize(ctx, authorizeInput(challenge), nil)
	if err != nil || !result.LoginRequired {
		t.Fatalf("anonymous Authorize = (%+v, %v), want LoginRequired", result, err)
	}

	// prompt=none without a session is a protocol error.
	noPrompt := authorizeInput(challenge)
	noPrompt.Prompt = PromptNone
	_, err = fx.provider.Authorize(ctx, noPrompt, nil)
	wantOAuthCode(t, err, ErrCodeLoginRequired)

	// First authorization needs consent.
	result, err = fx.provider.Authorize(ctx, authorizeInput(challenge), user)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if result.Consent == nil {
		t.Fatalf("Authorize = %+v, want consent required", result)
	}
	if result.Consent.ClientName != "Test App" || len(result.Consent.Scopes) != 2 {
		t.Fatalf("consent = %+v, want Test App with 2 scopes", result.Consent)
	}

	// Approve consent; a code is minted.
	outcome, err := fx.provider.DecideConsent(ctx, *user, result.Consent.AuthorizationID, true)
	if err != nil {
		t.Fatalf("DecideConsent: %v", err)
	}
	if outcome.Granted == nil || outcome.Granted.State != "state-1" {
		t.Fatalf("DecideConsent = %+v, want granted with state-1", outcome)
	}

	// Exchange the code with the right PKCE verifier.
	tokens, err := fx.provider.ExchangeToken(ctx, ExchangeInput{
		ClientID: "client-abc",
		Code: &CodeGrantInput{
			Code:         outcome.Granted.Code,
			RedirectURI:  "https://app.test/cb",
			CodeVerifier: verifier,
		},
	})
	if err != nil {
		t.Fatalf("ExchangeToken: %v", err)
	}
	if tokens.AccessToken == "" || tokens.IDToken == "" || tokens.RefreshToken == "" {
		t.Fatalf("tokens missing pieces: %+v", tokens)
	}

	claims, err := fx.verifier.VerifyAccessToken(ctx, tokens.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}
	if claims.UserID != fx.userID || claims.ClientID != "client-abc" {
		t.Fatalf("claims = %+v, want user %s client client-abc", claims, fx.userID)
	}

	// Codes are single-use.
	_, err = fx.provider.ExchangeToken(ctx, ExchangeInput{
		ClientID: "client-abc",
		Code: &CodeGrantInput{
			Code:         outcome.Granted.Code,
			RedirectURI:  "https://app.test/cb",
			CodeVerifier: verifier,
		},
	})
	wantOAuthCode(t, err, ErrCodeInvalidGrant)

	// Consent persists: the next authorize skips the consent screen.
	result, err = fx.provider.Authorize(ctx, authorizeInput(challenge), user)
	if err != nil {
		t.Fatalf("Authorize after consent: %v", err)
	}
	if result.Granted == nil {
		t.Fatalf("Authorize after consent = %+v, want granted", result)
	}
}

func TestExchangeTokenPKCEMismatch(t *testing.T) {
	t.Parallel()

	ctx, fx := newProviderFixture(t, "oidcpkce")
	user := &SessionUser{UserID: fx.userID, SessionID: uuid.New(), AuthTime: time.Now()}
	_, challenge := pkcePair()

	result, err := fx.provider.Authorize(ctx, authorizeInput(challenge), user)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	outcome, err := fx.provider.DecideConsent(ctx, *user, result.Consent.AuthorizationID, true)
	if err != nil {
		t.Fatalf("DecideConsent: %v", err)
	}

	tests := []struct {
		name     string
		verifier string
	}{
		{name: "wrong verifier", verifier: "wrong-verifier-wrong-verifier-wrong-43chars"},
		{name: "missing verifier", verifier: ""},
	}
	for _, tc := range tests {
		// Sequential: both consume attempts target the same single-use code,
		// and the first failure already burns it.
		_, err = fx.provider.ExchangeToken(ctx, ExchangeInput{
			ClientID: "client-abc",
			Code: &CodeGrantInput{
				Code:         outcome.Granted.Code,
				RedirectURI:  "https://app.test/cb",
				CodeVerifier: tc.verifier,
			},
		})
		wantOAuthCode(t, err, ErrCodeInvalidGrant)
	}
}

func TestConsentDeny(t *testing.T) {
	t.Parallel()

	ctx, fx := newProviderFixture(t, "oidcdeny")
	user := &SessionUser{UserID: fx.userID, SessionID: uuid.New(), AuthTime: time.Now()}
	_, challenge := pkcePair()

	result, err := fx.provider.Authorize(ctx, authorizeInput(challenge), user)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}

	outcome, err := fx.provider.DecideConsent(ctx, *user, result.Consent.AuthorizationID, false)
	if err != nil {
		t.Fatalf("DecideConsent deny: %v", err)
	}
	if outcome.Denied == nil || outcome.Denied.Err.Code != ErrCodeAccessDenied {
		t.Fatalf("DecideConsent deny = %+v, want access_denied", outcome)
	}
	if outcome.Denied.RedirectURI != "https://app.test/cb" || outcome.Denied.State != "state-1" {
		t.Fatalf("denied redirect = %+v, want stored redirect/state", outcome.Denied)
	}

	// The pending authorization is consumed either way.
	_, err = fx.provider.DecideConsent(ctx, *user, result.Consent.AuthorizationID, true)
	if !errors.Is(err, ErrPendingNotFound) {
		t.Fatalf("second DecideConsent err = %v, want ErrPendingNotFound", err)
	}
}

func TestRefreshRotationAndReuseDetection(t *testing.T) {
	t.Parallel()

	ctx, fx := newProviderFixture(t, "oidcrefresh")
	user := &SessionUser{UserID: fx.userID, SessionID: uuid.New(), AuthTime: time.Now()}
	verifier, challenge := pkcePair()

	result, err := fx.provider.Authorize(ctx, authorizeInput(challenge), user)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	outcome, err := fx.provider.DecideConsent(ctx, *user, result.Consent.AuthorizationID, true)
	if err != nil {
		t.Fatalf("DecideConsent: %v", err)
	}
	tokens, err := fx.provider.ExchangeToken(ctx, ExchangeInput{
		ClientID: "client-abc",
		Code: &CodeGrantInput{
			Code:         outcome.Granted.Code,
			RedirectURI:  "https://app.test/cb",
			CodeVerifier: verifier,
		},
	})
	if err != nil {
		t.Fatalf("ExchangeToken: %v", err)
	}

	// Rotate once.
	rotated, err := fx.provider.ExchangeToken(ctx, ExchangeInput{
		ClientID: "client-abc",
		Refresh:  &RefreshGrantInput{RefreshToken: tokens.RefreshToken},
	})
	if err != nil {
		t.Fatalf("refresh rotate: %v", err)
	}
	if rotated.RefreshToken == "" || rotated.RefreshToken == tokens.RefreshToken {
		t.Fatalf("rotation returned refresh token %q, want a new one", rotated.RefreshToken)
	}

	// Replaying the rotated-away token revokes the whole family.
	_, err = fx.provider.ExchangeToken(ctx, ExchangeInput{
		ClientID: "client-abc",
		Refresh:  &RefreshGrantInput{RefreshToken: tokens.RefreshToken},
	})
	wantOAuthCode(t, err, ErrCodeInvalidGrant)

	_, err = fx.provider.ExchangeToken(ctx, ExchangeInput{
		ClientID: "client-abc",
		Refresh:  &RefreshGrantInput{RefreshToken: rotated.RefreshToken},
	})
	wantOAuthCode(t, err, ErrCodeInvalidGrant)

	live, err := fx.db.OIDCRefreshToken.Query().
		Where(oidcrefreshtoken.RevokedAtIsNil()).
		Count(ctx)
	if err != nil {
		t.Fatalf("count live refresh tokens: %v", err)
	}
	if live != 0 {
		t.Fatalf("live refresh tokens after reuse = %d, want 0", live)
	}
}

func TestRefreshScopeNarrowing(t *testing.T) {
	t.Parallel()

	ctx, fx := newProviderFixture(t, "oidcnarrow")
	user := &SessionUser{UserID: fx.userID, SessionID: uuid.New(), AuthTime: time.Now()}
	verifier, challenge := pkcePair()

	result, err := fx.provider.Authorize(ctx, authorizeInput(challenge), user)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	outcome, err := fx.provider.DecideConsent(ctx, *user, result.Consent.AuthorizationID, true)
	if err != nil {
		t.Fatalf("DecideConsent: %v", err)
	}
	tokens, err := fx.provider.ExchangeToken(ctx, ExchangeInput{
		ClientID: "client-abc",
		Code: &CodeGrantInput{
			Code:         outcome.Granted.Code,
			RedirectURI:  "https://app.test/cb",
			CodeVerifier: verifier,
		},
	})
	if err != nil {
		t.Fatalf("ExchangeToken: %v", err)
	}

	// Widening beyond the original grant fails without consuming the token.
	_, err = fx.provider.ExchangeToken(ctx, ExchangeInput{
		ClientID: "client-abc",
		Refresh: &RefreshGrantInput{
			RefreshToken: tokens.RefreshToken,
			Scopes:       []string{ScopeOpenID, ScopeProfile},
		},
	})
	wantOAuthCode(t, err, ErrCodeInvalidScope)

	// Narrowing works.
	narrowed, err := fx.provider.ExchangeToken(ctx, ExchangeInput{
		ClientID: "client-abc",
		Refresh: &RefreshGrantInput{
			RefreshToken: tokens.RefreshToken,
			Scopes:       []string{ScopeOpenID},
		},
	})
	if err != nil {
		t.Fatalf("narrowed refresh: %v", err)
	}
	if len(narrowed.Scopes) != 1 || narrowed.Scopes[0] != ScopeOpenID {
		t.Fatalf("narrowed scopes = %v, want [openid]", narrowed.Scopes)
	}
}

func TestDeviceFlow(t *testing.T) {
	t.Parallel()

	ctx, fx := newProviderFixture(t, "oidcdevice")
	user := SessionUser{UserID: fx.userID, SessionID: uuid.New(), AuthTime: time.Now()}

	auth, err := fx.provider.StartDeviceAuthorization(
		ctx,
		"client-abc",
		"",
		[]string{ScopeOpenID},
	)
	if err != nil {
		t.Fatalf("StartDeviceAuthorization: %v", err)
	}
	if auth.UserCode == "" || auth.DeviceCode == "" || auth.ExpiresIn <= 0 {
		t.Fatalf("device authorization = %+v", auth)
	}

	poll := func() (TokenOutput, error) {
		// Outwait the poll throttle (test interval is 1ms).
		time.Sleep(5 * time.Millisecond)
		return fx.provider.ExchangeToken(ctx, ExchangeInput{
			ClientID: "client-abc",
			Device:   &DeviceGrantInput{DeviceCode: auth.DeviceCode},
		})
	}

	_, err = poll()
	wantOAuthCode(t, err, ErrCodeAuthorizationPending)

	// Polling without waiting trips the throttle.
	_, err = fx.provider.ExchangeToken(ctx, ExchangeInput{
		ClientID: "client-abc",
		Device:   &DeviceGrantInput{DeviceCode: auth.DeviceCode},
	})
	wantOAuthCode(t, err, ErrCodeSlowDown)

	info, err := fx.provider.DeviceAuthorizationInfo(ctx, "  "+auth.UserCode+" ")
	if err != nil {
		t.Fatalf("DeviceAuthorizationInfo: %v", err)
	}
	if info.ClientName != "Test App" {
		t.Fatalf("device info = %+v, want Test App", info)
	}

	err = fx.provider.DecideDeviceAuthorization(ctx, user, auth.UserCode, true)
	if err != nil {
		t.Fatalf("DecideDeviceAuthorization: %v", err)
	}

	tokens, err := poll()
	if err != nil {
		t.Fatalf("poll after approval: %v", err)
	}
	if tokens.AccessToken == "" || tokens.IDToken == "" {
		t.Fatalf("device tokens = %+v, want access + id token", tokens)
	}

	// The device code is consumed.
	_, err = poll()
	wantOAuthCode(t, err, ErrCodeExpiredToken)
}

func TestDeviceFlowDenied(t *testing.T) {
	t.Parallel()

	ctx, fx := newProviderFixture(t, "oidcdevicedeny")
	user := SessionUser{UserID: fx.userID, SessionID: uuid.New(), AuthTime: time.Now()}

	auth, err := fx.provider.StartDeviceAuthorization(ctx, "client-abc", "", []string{ScopeOpenID})
	if err != nil {
		t.Fatalf("StartDeviceAuthorization: %v", err)
	}
	err = fx.provider.DecideDeviceAuthorization(ctx, user, auth.UserCode, false)
	if err != nil {
		t.Fatalf("DecideDeviceAuthorization deny: %v", err)
	}

	time.Sleep(5 * time.Millisecond)
	_, err = fx.provider.ExchangeToken(ctx, ExchangeInput{
		ClientID: "client-abc",
		Device:   &DeviceGrantInput{DeviceCode: auth.DeviceCode},
	})
	wantOAuthCode(t, err, ErrCodeAccessDenied)
}

func TestExchangeTokenUnknownClient(t *testing.T) {
	t.Parallel()

	ctx, fx := newProviderFixture(t, "oidcnoclient")
	_, err := fx.provider.ExchangeToken(ctx, ExchangeInput{
		ClientID: "missing",
		Code:     &CodeGrantInput{Code: "x", RedirectURI: "https://app.test/cb"},
	})
	wantOAuthCode(t, err, ErrCodeInvalidClient)
}
