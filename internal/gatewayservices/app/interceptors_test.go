package app

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"sanzi.io/muid/pkg/gateway/jwtauth"
)

const testIssuer = "https://id.test"

type staticKeySource struct{ keys map[string]*rsa.PublicKey }

func (s staticKeySource) Keys(context.Context) (map[string]*rsa.PublicKey, error) {
	return s.keys, nil
}

func newVerifier(t *testing.T) (*jwtauth.Verifier, *rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	kid := uuid.NewString()
	v := jwtauth.NewVerifier(
		staticKeySource{keys: map[string]*rsa.PublicKey{kid: &key.PublicKey}},
		jwtauth.Config{Issuer: testIssuer},
	)
	return v, key, kid
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

func TestAuthInterceptorValidToken(t *testing.T) {
	t.Parallel()

	verifier, key, kid := newVerifier(t)
	sub := uuid.NewString()
	ctx := metadata.NewIncomingContext(context.Background(),
		metadata.Pairs("authorization", "Bearer "+mintToken(t, key, kid, sub)))

	var seen uuid.UUID
	_, err := authInterceptor(verifier)(ctx, nil, &grpc.UnaryServerInfo{}, func(ctx context.Context, _ any) (any, error) {
		if claims, ok := jwtauth.ClaimsFromContext(ctx); ok {
			seen = claims.UserID
		}
		return "ok", nil
	})
	if err != nil {
		t.Fatalf("interceptor: %v", err)
	}
	if seen.String() != sub {
		t.Fatalf("claims user id = %s, want %s", seen, sub)
	}
}

func TestAuthInterceptorInvalidToken(t *testing.T) {
	t.Parallel()

	verifier, _, _ := newVerifier(t)
	ctx := metadata.NewIncomingContext(context.Background(),
		metadata.Pairs("authorization", "Bearer garbage"))

	_, err := authInterceptor(verifier)(ctx, nil, &grpc.UnaryServerInfo{}, func(context.Context, any) (any, error) {
		t.Fatal("handler should not run for an invalid token")
		return nil, nil
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated, got %v", err)
	}
}

func TestAuthInterceptorRejectsAnonymous(t *testing.T) {
	t.Parallel()

	verifier, _, _ := newVerifier(t)
	_, err := authInterceptor(verifier)(context.Background(), nil, &grpc.UnaryServerInfo{}, func(context.Context, any) (any, error) {
		t.Fatal("handler should not run for an anonymous request")
		return nil, nil
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated for anonymous request, got %v", err)
	}
}
