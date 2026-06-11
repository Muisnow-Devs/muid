package oidctoken

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	gcpsecretmanager "sanzi.io/muid/infra/secretmanager"
	"sanzi.io/muid/internal/signature"
)

func newTestSigner(t *testing.T) (context.Context, *Signer, *Verifier) {
	t.Helper()

	ctx := context.Background()
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

	return ctx, NewSigner(manager, "https://id.test"), NewVerifier(manager, "https://id.test")
}

func decodeSegment(t *testing.T, token string, index int) map[string]any {
	t.Helper()

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d segments, want 3", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[index])
	if err != nil {
		t.Fatalf("decode segment %d: %v", index, err)
	}
	out := map[string]any{}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal segment %d: %v", index, err)
	}
	return out
}

func TestAccessTokenRoundTrip(t *testing.T) {
	t.Parallel()

	ctx, signer, verifier := newTestSigner(t)
	userID := uuid.New()
	jti := uuid.New()

	token, err := signer.CreateAccessToken(ctx, AccessTokenClaims{
		UserID:   userID,
		ClientID: "client-abc",
		Scopes:   []string{"openid", "profile"},
		JTI:      jti,
	})
	if err != nil {
		t.Fatalf("CreateAccessToken: %v", err)
	}

	header := decodeSegment(t, token, 0)
	if header["alg"] != "RS256" || header["kid"] == nil || header["kid"] == "" {
		t.Fatalf("header = %v, want RS256 with kid", header)
	}

	claims, err := verifier.VerifyAccessToken(ctx, token)
	if err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}
	if claims.UserID != userID || claims.ClientID != "client-abc" || claims.JTI != jti {
		t.Fatalf(
			"claims = (user %s, client %q, jti %s), want (%s, client-abc, %s)",
			claims.UserID, claims.ClientID, claims.JTI, userID, jti,
		)
	}
	if len(claims.Scopes) != 2 || claims.Scopes[0] != "openid" || claims.Scopes[1] != "profile" {
		t.Fatalf("scopes = %v, want [openid profile]", claims.Scopes)
	}
}

func TestVerifyAccessTokenRejections(t *testing.T) {
	t.Parallel()

	ctx, signer, verifier := newTestSigner(t)
	userID := uuid.New()

	expired, err := signer.CreateAccessToken(ctx, AccessTokenClaims{
		UserID:    userID,
		ClientID:  "client-abc",
		IssuedAt:  time.Now().Add(-2 * time.Hour),
		ExpiresAt: time.Now().Add(-time.Hour),
	})
	if err != nil {
		t.Fatalf("CreateAccessToken expired: %v", err)
	}

	valid, err := signer.CreateAccessToken(ctx, AccessTokenClaims{
		UserID:   userID,
		ClientID: "client-abc",
	})
	if err != nil {
		t.Fatalf("CreateAccessToken valid: %v", err)
	}
	parts := strings.Split(valid, ".")
	tampered := parts[0] + "." + base64.RawURLEncoding.EncodeToString(
		[]byte(`{"sub":"`+userID.String()+`","iss":"https://id.test"}`),
	) + "." + parts[2]

	tests := []struct {
		name    string
		token   string
		wantErr error
	}{
		{name: "expired", token: expired, wantErr: ErrExpiredToken},
		{name: "garbage", token: "not-a-token", wantErr: ErrInvalidToken},
		{name: "tampered payload", token: tampered, wantErr: ErrInvalidToken},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := verifier.VerifyAccessToken(ctx, tc.token)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("VerifyAccessToken err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestVerifyAccessTokenWrongIssuer(t *testing.T) {
	t.Parallel()

	ctx, signer, _ := newTestSigner(t)
	token, err := signer.CreateAccessToken(ctx, AccessTokenClaims{
		UserID:   uuid.New(),
		ClientID: "client-abc",
	})
	if err != nil {
		t.Fatalf("CreateAccessToken: %v", err)
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

	_, err = NewVerifier(manager, "https://other.test").VerifyAccessToken(ctx, token)
	if !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("VerifyAccessToken err = %v, want ErrInvalidToken", err)
	}
}

func TestCreateIDTokenClaims(t *testing.T) {
	t.Parallel()

	ctx, signer, _ := newTestSigner(t)
	userID := uuid.New()
	authTime := time.Now().Add(-time.Minute).Truncate(time.Second)
	verified := true

	token, err := signer.CreateIDToken(ctx, IDTokenClaims{
		UserID:            userID,
		ClientID:          "client-abc",
		Nonce:             "nonce-123",
		AuthTime:          authTime,
		Name:              "Test User",
		Picture:           "https://img.test/a.png",
		PreferredUsername: "testuser",
		Locale:            "en",
		Zoneinfo:          "Asia/Taipei",
		Email:             "user@test.example",
		EmailVerified:     &verified,
	})
	if err != nil {
		t.Fatalf("CreateIDToken: %v", err)
	}

	payload := decodeSegment(t, token, 1)
	checks := map[string]any{
		"iss":                "https://id.test",
		"sub":                userID.String(),
		"azp":                "client-abc",
		"nonce":              "nonce-123",
		"name":               "Test User",
		"picture":            "https://img.test/a.png",
		"preferred_username": "testuser",
		"locale":             "en",
		"zoneinfo":           "Asia/Taipei",
		"email":              "user@test.example",
		"email_verified":     true,
		"auth_time":          float64(authTime.Unix()),
	}
	for key, want := range checks {
		if payload[key] != want {
			t.Fatalf("claim %q = %v, want %v", key, payload[key], want)
		}
	}
	aud, ok := payload["aud"].([]any)
	if !ok || len(aud) != 1 || aud[0] != "client-abc" {
		t.Fatalf("aud = %v, want [client-abc]", payload["aud"])
	}
}

func TestCreateIDTokenOmitsUnsetClaims(t *testing.T) {
	t.Parallel()

	ctx, signer, _ := newTestSigner(t)
	token, err := signer.CreateIDToken(ctx, IDTokenClaims{
		UserID:   uuid.New(),
		ClientID: "client-abc",
	})
	if err != nil {
		t.Fatalf("CreateIDToken: %v", err)
	}

	payload := decodeSegment(t, token, 1)
	absentClaims := []string{
		"nonce", "name", "picture", "preferred_username", "locale", "zoneinfo",
		"email", "email_verified", "auth_time",
	}
	for _, absent := range absentClaims {
		if _, ok := payload[absent]; ok {
			t.Fatalf("claim %q present, want omitted", absent)
		}
	}
}
