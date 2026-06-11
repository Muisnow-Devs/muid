package oidctoken

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"sanzi.io/muid/internal/signature"
)

// clockSkewLeeway tolerates small clock differences between services when
// validating iat/exp.
const clockSkewLeeway = 60 * time.Second

var (
	// ErrInvalidToken indicates the token is malformed, has a bad signature,
	// or was issued by a different issuer.
	ErrInvalidToken = errors.New("oidctoken: invalid token")
	// ErrExpiredToken indicates the token is structurally valid but expired.
	ErrExpiredToken = errors.New("oidctoken: expired token")
)

// Verifier validates access tokens minted by Signer.
type Verifier struct {
	signing signature.SignatureManager
	issuer  string
}

func NewVerifier(signing signature.SignatureManager, issuer string) *Verifier {
	return &Verifier{
		signing: signing,
		issuer:  strings.TrimSpace(issuer),
	}
}

// VerifyAccessToken checks the signature and registered claims of raw and
// returns the embedded access token claims.
func (v *Verifier) VerifyAccessToken(
	ctx context.Context,
	raw string,
) (AccessTokenClaims, error) {
	if v == nil || v.signing == nil {
		return AccessTokenClaims{}, signature.ErrInvalidConfig
	}

	var payload accessTokenJWTClaims
	token, parts, err := jwt.NewParser().ParseUnverified(strings.TrimSpace(raw), &payload)
	if err != nil {
		return AccessTokenClaims{}, errors.Join(ErrInvalidToken, err)
	}

	alg, _ := token.Header["alg"].(string)
	if alg != signature.AlgorithmRS256 {
		return AccessTokenClaims{}, ErrInvalidToken
	}
	kid, _ := token.Header["kid"].(string)
	if strings.TrimSpace(kid) == "" {
		return AccessTokenClaims{}, ErrInvalidToken
	}

	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return AccessTokenClaims{}, errors.Join(ErrInvalidToken, err)
	}
	valid, err := v.signing.Verify(ctx, []byte(parts[0]+"."+parts[1]), signature.Signature{
		KeyID:     kid,
		Alg:       signature.AlgorithmRS256,
		Signature: sigBytes,
	})
	if err != nil {
		return AccessTokenClaims{}, err
	}
	if !valid {
		return AccessTokenClaims{}, ErrInvalidToken
	}

	return validateAccessClaims(v.issuer, payload)
}

func validateAccessClaims(
	issuer string,
	payload accessTokenJWTClaims,
) (AccessTokenClaims, error) {
	if payload.Issuer != issuer {
		return AccessTokenClaims{}, ErrInvalidToken
	}
	if payload.ExpiresAt == nil || payload.IssuedAt == nil {
		return AccessTokenClaims{}, ErrInvalidToken
	}

	now := time.Now()
	if now.After(payload.ExpiresAt.Time.Add(clockSkewLeeway)) {
		return AccessTokenClaims{}, ErrExpiredToken
	}
	if payload.IssuedAt.Time.After(now.Add(clockSkewLeeway)) {
		return AccessTokenClaims{}, ErrInvalidToken
	}

	userID, err := uuid.Parse(payload.Subject)
	if err != nil {
		return AccessTokenClaims{}, errors.Join(ErrInvalidToken, err)
	}

	claims := AccessTokenClaims{
		UserID:    userID,
		ClientID:  payload.ClientID,
		Audience:  payload.Audience,
		IssuedAt:  payload.IssuedAt.Time,
		ExpiresAt: payload.ExpiresAt.Time,
	}
	if payload.Scope != "" {
		claims.Scopes = strings.Fields(payload.Scope)
	}
	if jti, parseErr := uuid.Parse(payload.ID); parseErr == nil {
		claims.JTI = jti
	}
	return claims, nil
}
