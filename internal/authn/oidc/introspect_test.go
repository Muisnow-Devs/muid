package oidc

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"

	"sanzi.io/muid/internal/authn/ent/oidcclient"
)

// issueTokensForTest walks the full code flow and returns the token set.
func issueTokensForTest(
	t *testing.T,
	ctx context.Context,
	fx providerFixture,
) TokenOutput {
	t.Helper()

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
	return tokens
}

// addConfidentialSecret upgrades the fixture client to client_secret_post
// with a known secret.
func addConfidentialSecret(t *testing.T, ctx context.Context, fx providerFixture) string {
	t.Helper()

	secret := "super-secret-value"
	err := fx.db.OIDCClient.UpdateOneID(fx.client.ID).
		SetTokenEndpointAuthMethod(oidcclient.TokenEndpointAuthMethodClientSecretPost).
		Exec(ctx)
	if err != nil {
		t.Fatalf("set auth method: %v", err)
	}
	err = fx.db.OIDCClientSecret.Create().
		SetClientRefID(fx.client.ID).
		SetSecretHash(HashClientSecret(secret)).
		SetHint("super…alue").
		Exec(ctx)
	if err != nil {
		t.Fatalf("create client secret: %v", err)
	}
	return secret
}

func TestIntrospectToken(t *testing.T) {
	t.Parallel()

	ctx, fx := newProviderFixture(t, "oidcintrospect")
	tokens := issueTokensForTest(t, ctx, fx)
	secret := addConfidentialSecret(t, ctx, fx)

	// Public clients (no secret) are rejected.
	_, err := fx.provider.IntrospectToken(ctx, "client-abc", "", tokens.AccessToken, "")
	wantOAuthCode(t, err, ErrCodeInvalidClient)

	access, err := fx.provider.IntrospectToken(ctx, "client-abc", secret, tokens.AccessToken, "")
	if err != nil {
		t.Fatalf("introspect access token: %v", err)
	}
	if !access.Active || access.TokenType != TokenTypeAccessToken ||
		access.Subject != fx.userID {
		t.Fatalf("access introspection = %+v", access)
	}

	refresh, err := fx.provider.IntrospectToken(
		ctx, "client-abc", secret, tokens.RefreshToken, TokenTypeRefreshToken,
	)
	if err != nil {
		t.Fatalf("introspect refresh token: %v", err)
	}
	if !refresh.Active || refresh.TokenType != TokenTypeRefreshToken ||
		refresh.ClientID != "client-abc" {
		t.Fatalf("refresh introspection = %+v", refresh)
	}

	unknown, err := fx.provider.IntrospectToken(ctx, "client-abc", secret, "garbage", "")
	if err != nil {
		t.Fatalf("introspect unknown token: %v", err)
	}
	if unknown.Active {
		t.Fatal("unknown token introspected as active")
	}
}

func TestRevokeTokenRevokesFamily(t *testing.T) {
	t.Parallel()

	ctx, fx := newProviderFixture(t, "oidcrevoke")
	tokens := issueTokensForTest(t, ctx, fx)

	// Unknown tokens still succeed (RFC 7009).
	err := fx.provider.RevokeToken(ctx, "client-abc", "", "garbage")
	if err != nil {
		t.Fatalf("RevokeToken unknown: %v", err)
	}

	err = fx.provider.RevokeToken(ctx, "client-abc", "", tokens.RefreshToken)
	if err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}

	_, err = fx.provider.ExchangeToken(ctx, ExchangeInput{
		ClientID: "client-abc",
		Refresh:  &RefreshGrantInput{RefreshToken: tokens.RefreshToken},
	})
	wantOAuthCode(t, err, ErrCodeInvalidGrant)
}

func TestUserInfo(t *testing.T) {
	t.Parallel()

	ctx, fx := newProviderFixture(t, "oidcuserinfo")

	// Seed a primary email so the email scope yields claims.
	identityID := uuid.New()
	err := fx.db.UserIdentity.Create().
		SetID(identityID).
		SetUserID(fx.userID).
		SetProvider("email").
		SetSubject("user@test.example").
		Exec(ctx)
	if err != nil {
		t.Fatalf("create identity: %v", err)
	}
	err = fx.db.UserEmail.Create().
		SetID(uuid.New()).
		SetIdentityID(identityID).
		SetUserID(fx.userID).
		SetEmail("user@test.example").
		SetIsPrimary(true).
		Exec(ctx)
	if err != nil {
		t.Fatalf("create email: %v", err)
	}

	tokens := issueTokensForTest(t, ctx, fx)

	info, err := fx.provider.UserInfo(ctx, tokens.AccessToken)
	if err != nil {
		t.Fatalf("UserInfo: %v", err)
	}
	if info.Subject != fx.userID {
		t.Fatalf("sub = %s, want %s", info.Subject, fx.userID)
	}
	if info.Email == nil || *info.Email != "user@test.example" ||
		info.EmailVerified == nil || !*info.EmailVerified {
		t.Fatalf("email claims = %+v, want verified user@test.example", info)
	}

	_, err = fx.provider.UserInfo(ctx, "garbage")
	wantOAuthCode(t, err, ErrCodeInvalidToken)
}

func TestConsentListAndRevoke(t *testing.T) {
	t.Parallel()

	ctx, fx := newProviderFixture(t, "oidcconsents")
	tokens := issueTokensForTest(t, ctx, fx)

	consents, err := fx.provider.ListGrantedConsents(ctx, fx.userID)
	if err != nil {
		t.Fatalf("ListGrantedConsents: %v", err)
	}
	if len(consents) != 1 || consents[0].ClientID != "client-abc" {
		t.Fatalf("consents = %+v, want one for client-abc", consents)
	}

	revoked, err := fx.provider.RevokeConsent(ctx, fx.userID, "client-abc")
	if err != nil {
		t.Fatalf("RevokeConsent: %v", err)
	}
	if !revoked {
		t.Fatal("RevokeConsent = false, want true")
	}

	// Refresh tokens die with the consent.
	_, err = fx.provider.ExchangeToken(ctx, ExchangeInput{
		ClientID: "client-abc",
		Refresh:  &RefreshGrantInput{RefreshToken: tokens.RefreshToken},
	})
	wantOAuthCode(t, err, ErrCodeInvalidGrant)

	consents, err = fx.provider.ListGrantedConsents(ctx, fx.userID)
	if err != nil {
		t.Fatalf("ListGrantedConsents after revoke: %v", err)
	}
	if len(consents) != 0 {
		t.Fatalf("consents after revoke = %+v, want none", consents)
	}

	// And the next authorize requires consent again.
	user := &SessionUser{UserID: fx.userID, SessionID: uuid.New(), AuthTime: time.Now()}
	_, challenge := pkcePair()
	result, err := fx.provider.Authorize(ctx, authorizeInput(challenge), user)
	if err != nil {
		t.Fatalf("Authorize after revoke: %v", err)
	}
	if result.Consent == nil {
		t.Fatalf("Authorize after revoke = %+v, want consent required", result)
	}
}

func TestPrivateAccessPolicyAllowlist(t *testing.T) {
	t.Parallel()

	ctx, fx := newProviderFixture(t, "oidcprivate")
	err := fx.db.OIDCClient.UpdateOneID(fx.client.ID).
		SetAccessPolicy(oidcclient.AccessPolicyPrivate).
		Exec(ctx)
	if err != nil {
		t.Fatalf("set access policy: %v", err)
	}

	user := &SessionUser{UserID: fx.userID, SessionID: uuid.New(), AuthTime: time.Now()}
	_, challenge := pkcePair()

	_, err = fx.provider.Authorize(ctx, authorizeInput(challenge), user)
	wantOAuthCode(t, err, ErrCodeAccessDenied)

	err = fx.db.OIDCClientAccessGrant.Create().
		SetClientRefID(fx.client.ID).
		SetUserID(fx.userID).
		Exec(ctx)
	if err != nil {
		t.Fatalf("create access grant: %v", err)
	}

	result, err := fx.provider.Authorize(ctx, authorizeInput(challenge), user)
	if err != nil {
		t.Fatalf("Authorize allowlisted: %v", err)
	}
	if result.Consent == nil {
		t.Fatalf("Authorize allowlisted = %+v, want consent required", result)
	}
}
