package jwtauth_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"sanzi.io/muid/pkg/gateway/jwtauth"
)

const testIssuer = "https://id.test"

type staticKeySource struct {
	keys  map[string]*rsa.PublicKey
	calls int
}

func (s *staticKeySource) Keys(context.Context) (map[string]*rsa.PublicKey, error) {
	s.calls++
	return s.keys, nil
}

type signedTokenOpts struct {
	kid       string
	typ       string
	tokenUse  string
	issuer    string
	subject   string
	audience  []string
	expiresAt time.Time
}

func mintToken(t *testing.T, key *rsa.PrivateKey, o signedTokenOpts) string {
	t.Helper()
	claims := jwt.MapClaims{
		"token_use": o.tokenUse,
		"sub":       o.subject,
		"iss":       o.issuer,
		"iat":       jwt.NewNumericDate(time.Now()),
		"exp":       jwt.NewNumericDate(o.expiresAt),
		"email":     "user@test",
	}
	if len(o.audience) > 0 {
		claims["aud"] = o.audience
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["typ"] = o.typ
	token.Header["kid"] = o.kid
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}

func newVerifier(t *testing.T) (*jwtauth.Verifier, *rsa.PrivateKey, string) {
	t.Helper()
	return newVerifierWithConfig(t, jwtauth.Config{Issuer: testIssuer})
}

func newVerifierWithConfig(
	t *testing.T,
	cfg jwtauth.Config,
) (*jwtauth.Verifier, *rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	kid := uuid.NewString()
	src := &staticKeySource{keys: map[string]*rsa.PublicKey{kid: &key.PublicKey}}
	v := jwtauth.NewVerifier(src, cfg)
	return v, key, kid
}

func TestVerifyRequiredAudience(t *testing.T) {
	t.Parallel()

	verifier, key, kid := newVerifierWithConfig(t, jwtauth.Config{
		Issuer:           testIssuer,
		RequiredAudience: "gateway-services",
	})
	base := signedTokenOpts{
		kid:       kid,
		typ:       "muid-session+jwt",
		tokenUse:  "session",
		issuer:    testIssuer,
		subject:   uuid.NewString(),
		expiresAt: time.Now().Add(2 * time.Minute),
	}
	tests := []struct {
		name     string
		audience []string
		wantErr  bool
	}{
		{name: "missing audience", wantErr: true},
		{name: "wrong audience", audience: []string{"authn-account"}, wantErr: true},
		{
			name:     "required audience present",
			audience: []string{"gateway-services", "authn-account"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			opts := base
			opts.audience = test.audience
			_, err := verifier.Verify(t.Context(), mintToken(t, key, opts))
			if test.wantErr && !errors.Is(err, jwtauth.ErrInvalidToken) {
				t.Fatalf("Verify() error = %v, want ErrInvalidToken", err)
			}
			if !test.wantErr && err != nil {
				t.Fatalf("Verify() error = %v", err)
			}
		})
	}
}

func TestVerifyContextPreservesRawBearerOnlyOnSuccess(t *testing.T) {
	t.Parallel()

	verifier, key, kid := newVerifier(t)
	raw := mintToken(t, key, signedTokenOpts{
		kid:       kid,
		typ:       "muid-session+jwt",
		tokenUse:  "session",
		issuer:    testIssuer,
		subject:   uuid.NewString(),
		expiresAt: time.Now().Add(2 * time.Minute),
	})

	verifiedCtx, err := verifier.VerifyContext(t.Context(), raw)
	if err != nil {
		t.Fatalf("VerifyContext() error = %v", err)
	}
	got, ok := jwtauth.RawBearerFromContext(verifiedCtx)
	if !ok || got != raw {
		t.Fatalf("RawBearerFromContext() = (%q, %t), want exact bearer", got, ok)
	}
	if _, ok := jwtauth.ClaimsFromContext(verifiedCtx); !ok {
		t.Fatal("ClaimsFromContext() missing verified claims")
	}

	failedCtx, err := verifier.VerifyContext(t.Context(), "invalid")
	if !errors.Is(err, jwtauth.ErrInvalidToken) {
		t.Fatalf("VerifyContext(invalid) error = %v, want ErrInvalidToken", err)
	}
	if got, ok := jwtauth.RawBearerFromContext(failedCtx); ok {
		t.Fatalf("invalid token retained raw bearer %q", got)
	}
	if _, ok := jwtauth.ClaimsFromContext(failedCtx); ok {
		t.Fatal("invalid token retained claims")
	}
}

func TestVerifyValidToken(t *testing.T) {
	t.Parallel()

	v, key, kid := newVerifier(t)
	sub := uuid.NewString()
	raw := mintToken(t, key, signedTokenOpts{
		kid:       kid,
		typ:       "muid-session+jwt",
		tokenUse:  "session",
		issuer:    testIssuer,
		subject:   sub,
		expiresAt: time.Now().Add(2 * time.Minute),
	})

	claims, err := v.Verify(context.Background(), raw)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.UserID.String() != sub {
		t.Fatalf("UserID = %s, want %s", claims.UserID, sub)
	}
	if claims.Email != "user@test" {
		t.Fatalf("Email = %q", claims.Email)
	}
}

func TestVerifyRejectsOIDCTyp(t *testing.T) {
	t.Parallel()

	v, key, kid := newVerifier(t)
	raw := mintToken(t, key, signedTokenOpts{
		kid:       kid,
		typ:       "JWT", // OIDC provider token, not a session token
		tokenUse:  "session",
		issuer:    testIssuer,
		subject:   uuid.NewString(),
		expiresAt: time.Now().Add(2 * time.Minute),
	})

	if _, err := v.Verify(context.Background(), raw); !errors.Is(err, jwtauth.ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken for typ=JWT, got %v", err)
	}
}

func TestVerifyRejectsWrongTokenUse(t *testing.T) {
	t.Parallel()

	v, key, kid := newVerifier(t)
	raw := mintToken(t, key, signedTokenOpts{
		kid:       kid,
		typ:       "muid-session+jwt",
		tokenUse:  "id", // wrong discriminator
		issuer:    testIssuer,
		subject:   uuid.NewString(),
		expiresAt: time.Now().Add(2 * time.Minute),
	})

	if _, err := v.Verify(context.Background(), raw); !errors.Is(err, jwtauth.ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken for token_use=id, got %v", err)
	}
}

func TestVerifyRejectsExpired(t *testing.T) {
	t.Parallel()

	v, key, kid := newVerifier(t)
	raw := mintToken(t, key, signedTokenOpts{
		kid:       kid,
		typ:       "muid-session+jwt",
		tokenUse:  "session",
		issuer:    testIssuer,
		subject:   uuid.NewString(),
		expiresAt: time.Now().Add(-10 * time.Minute),
	})

	if _, err := v.Verify(context.Background(), raw); !errors.Is(err, jwtauth.ErrExpiredToken) {
		t.Fatalf("expected ErrExpiredToken, got %v", err)
	}
}

func TestVerifyRejectsWrongIssuer(t *testing.T) {
	t.Parallel()

	v, key, kid := newVerifier(t)
	raw := mintToken(t, key, signedTokenOpts{
		kid:       kid,
		typ:       "muid-session+jwt",
		tokenUse:  "session",
		issuer:    "https://evil",
		subject:   uuid.NewString(),
		expiresAt: time.Now().Add(2 * time.Minute),
	})

	if _, err := v.Verify(context.Background(), raw); !errors.Is(err, jwtauth.ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken for wrong issuer, got %v", err)
	}
}

func TestVerifyUnknownKidRefetchesOnce(t *testing.T) {
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	src := &staticKeySource{keys: map[string]*rsa.PublicKey{}} // empty: kid never present
	v := jwtauth.NewVerifier(src, jwtauth.Config{Issuer: testIssuer})

	raw := mintToken(t, key, signedTokenOpts{
		kid:       "missing",
		typ:       "muid-session+jwt",
		tokenUse:  "session",
		issuer:    testIssuer,
		subject:   uuid.NewString(),
		expiresAt: time.Now().Add(2 * time.Minute),
	})

	if _, err := v.Verify(context.Background(), raw); !errors.Is(err, jwtauth.ErrUnknownKey) {
		t.Fatalf("expected ErrUnknownKey, got %v", err)
	}
	if src.calls < 2 {
		t.Fatalf("expected a forced refetch on kid miss, got %d calls", src.calls)
	}
}
