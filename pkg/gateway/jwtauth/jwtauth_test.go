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
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	kid := uuid.NewString()
	src := &staticKeySource{keys: map[string]*rsa.PublicKey{kid: &key.PublicKey}}
	v := jwtauth.NewVerifier(src, jwtauth.Config{Issuer: testIssuer})
	return v, key, kid
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
