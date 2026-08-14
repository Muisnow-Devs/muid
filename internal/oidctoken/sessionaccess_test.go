package oidctoken

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"

	gcpsecretmanager "sanzi.io/muid/infra/secretmanager"
	"sanzi.io/muid/internal/signature"
)

func TestSessionAccessTokenRoundTrip(t *testing.T) {
	t.Parallel()

	ctx, signer, verifier := newTestSigner(t)
	userID := uuid.New()
	jti := uuid.New()

	token, err := signer.CreateSessionAccessToken(ctx, SessionAccessTokenClaims{
		UserID:            userID,
		Email:             "user@test.example",
		PreferredUsername: "testuser",
		Name:              "Test User",
		Picture:           "https://img.test/a.png",
		JTI:               jti,
	})
	if err != nil {
		t.Fatalf("CreateSessionAccessToken: %v", err)
	}

	header := decodeSegment(t, token, 0)
	if header["alg"] != "RS256" || header["kid"] == nil || header["kid"] == "" {
		t.Fatalf("header = %v, want RS256 with kid", header)
	}
	if header["typ"] != sessionAccessTokenTyp {
		t.Fatalf("header typ = %v, want %q", header["typ"], sessionAccessTokenTyp)
	}

	payload := decodeSegment(t, token, 1)
	checks := map[string]any{
		"iss":                "https://id.test",
		"sub":                userID.String(),
		"token_use":          sessionTokenUse,
		"email":              "user@test.example",
		"preferred_username": "testuser",
		"name":               "Test User",
		"picture":            "https://img.test/a.png",
		"jti":                jti.String(),
	}
	for key, want := range checks {
		if payload[key] != want {
			t.Fatalf("claim %q = %v, want %v", key, payload[key], want)
		}
	}
	wantAudience := []any{sessionAudienceGatewayServices, sessionAudienceAuthnAccount}
	if audience, ok := payload["aud"].([]any); !ok || !reflect.DeepEqual(audience, wantAudience) {
		t.Fatalf("claim %q = %v, want %v", "aud", payload["aud"], wantAudience)
	}

	claims, err := verifier.VerifySessionAccessToken(ctx, token)
	if err != nil {
		t.Fatalf("VerifySessionAccessToken: %v", err)
	}
	if claims.UserID != userID || claims.JTI != jti {
		t.Fatalf("claims = (user %s, jti %s), want (%s, %s)",
			claims.UserID, claims.JTI, userID, jti)
	}
	if claims.Email != "user@test.example" || claims.PreferredUsername != "testuser" ||
		claims.Name != "Test User" || claims.Picture != "https://img.test/a.png" {
		t.Fatalf("identity claims = %+v", claims)
	}
}

func TestSessionAccessTokenClampsTTL(t *testing.T) {
	t.Parallel()

	ctx, signer, verifier := newTestSigner(t)
	issued := time.Now()

	token, err := signer.CreateSessionAccessToken(ctx, SessionAccessTokenClaims{
		UserID:    uuid.New(),
		IssuedAt:  issued,
		ExpiresAt: issued.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("CreateSessionAccessToken: %v", err)
	}

	claims, err := verifier.VerifySessionAccessToken(ctx, token)
	if err != nil {
		t.Fatalf("VerifySessionAccessToken: %v", err)
	}
	if got := claims.ExpiresAt.Sub(claims.IssuedAt); got > MaxSessionAccessTokenTTL {
		t.Fatalf("lifetime = %v, want <= %v", got, MaxSessionAccessTokenTTL)
	}
}

func TestSessionAccessTokenRequiresUserID(t *testing.T) {
	t.Parallel()

	ctx, signer, _ := newTestSigner(t)
	_, err := signer.CreateSessionAccessToken(ctx, SessionAccessTokenClaims{})
	if !errors.Is(err, signature.ErrSignFailed) {
		t.Fatalf("CreateSessionAccessToken err = %v, want ErrSignFailed", err)
	}
}

// TestTokenTypeSeparation pins the bidirectional rejection between session
// access tokens and OIDC provider tokens signed with the same keys.
func TestTokenTypeSeparation(t *testing.T) {
	t.Parallel()

	ctx, signer, verifier := newTestSigner(t)
	userID := uuid.New()

	sessionToken, err := signer.CreateSessionAccessToken(ctx, SessionAccessTokenClaims{
		UserID: userID,
	})
	if err != nil {
		t.Fatalf("CreateSessionAccessToken: %v", err)
	}
	oidcAccessToken, err := signer.CreateAccessToken(ctx, AccessTokenClaims{
		UserID:   userID,
		ClientID: "client-abc",
	})
	if err != nil {
		t.Fatalf("CreateAccessToken: %v", err)
	}
	idToken, err := signer.CreateIDToken(ctx, IDTokenClaims{
		UserID:   userID,
		ClientID: "client-abc",
	})
	if err != nil {
		t.Fatalf("CreateIDToken: %v", err)
	}

	t.Run("oidc verifier rejects session token", func(t *testing.T) {
		t.Parallel()
		_, err := verifier.VerifyAccessToken(ctx, sessionToken)
		if !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("VerifyAccessToken err = %v, want ErrInvalidToken", err)
		}
	})
	t.Run("session verifier rejects oidc access token", func(t *testing.T) {
		t.Parallel()
		_, err := verifier.VerifySessionAccessToken(ctx, oidcAccessToken)
		if !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("VerifySessionAccessToken err = %v, want ErrInvalidToken", err)
		}
	})
	t.Run("session verifier rejects id token", func(t *testing.T) {
		t.Parallel()
		_, err := verifier.VerifySessionAccessToken(ctx, idToken)
		if !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("VerifySessionAccessToken err = %v, want ErrInvalidToken", err)
		}
	})
}

func TestVerifySessionAccessTokenRejections(t *testing.T) {
	t.Parallel()

	ctx, signer, verifier := newTestSigner(t)
	userID := uuid.New()

	expired, err := signer.CreateSessionAccessToken(ctx, SessionAccessTokenClaims{
		UserID:    userID,
		IssuedAt:  time.Now().Add(-time.Hour),
		ExpiresAt: time.Now().Add(-30 * time.Minute),
	})
	if err != nil {
		t.Fatalf("CreateSessionAccessToken expired: %v", err)
	}

	tests := []struct {
		name    string
		token   string
		wantErr error
	}{
		{name: "expired", token: expired, wantErr: ErrExpiredToken},
		{name: "garbage", token: "not-a-token", wantErr: ErrInvalidToken},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := verifier.VerifySessionAccessToken(ctx, tc.token)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("VerifySessionAccessToken err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestVerifySessionAccessTokenWrongIssuer(t *testing.T) {
	t.Parallel()

	ctx, signer, _ := newTestSigner(t)
	token, err := signer.CreateSessionAccessToken(ctx, SessionAccessTokenClaims{
		UserID: uuid.New(),
	})
	if err != nil {
		t.Fatalf("CreateSessionAccessToken: %v", err)
	}

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

	_, err = NewVerifier(manager, "https://other.test").VerifySessionAccessToken(ctx, token)
	if !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("VerifySessionAccessToken err = %v, want ErrInvalidToken", err)
	}
}
