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

const (
	// sessionAccessTokenTyp is the explicit JWS header typ (RFC 8725) that
	// separates session access tokens from OIDC provider tokens (typ "JWT")
	// signed with the same keys.
	sessionAccessTokenTyp = "muid-session+jwt"
	// sessionTokenUse is the token_use claim value, a second discriminator.
	sessionTokenUse = "session"
	// Session access tokens declare both first-party consumer audiences.
	sessionAudienceGatewayServices = "gateway-services"
	sessionAudienceAuthnAccount    = "authn-account"

	// MaxSessionAccessTokenTTL caps the session access token lifetime.
	MaxSessionAccessTokenTTL = 5 * time.Minute
)

// SessionAccessTokenClaims describes the short-lived JWT issued alongside an
// opaque session token for CDN/gateway fast-path verification. Profile claims
// are best-effort: leave them zero when unavailable.
type SessionAccessTokenClaims struct {
	UserID            uuid.UUID
	Email             string
	PreferredUsername string
	Name              string
	Picture           string
	JTI               uuid.UUID
	IssuedAt          time.Time
	ExpiresAt         time.Time
}

type sessionAccessJWTClaims struct {
	TokenUse          string `json:"token_use"`
	Email             string `json:"email,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	Name              string `json:"name,omitempty"`
	Picture           string `json:"picture,omitempty"`
	jwt.RegisteredClaims
}

// CreateSessionAccessToken signs claims as a session access token. The
// lifetime is clamped to MaxSessionAccessTokenTTL regardless of the requested
// ExpiresAt.
func (s *Signer) CreateSessionAccessToken(
	ctx context.Context,
	claims SessionAccessTokenClaims,
) (string, error) {
	if s == nil || s.signing == nil {
		return "", signature.ErrInvalidConfig
	}
	if claims.UserID == uuid.Nil {
		return "", signature.ErrSignFailed
	}

	if claims.IssuedAt.IsZero() {
		claims.IssuedAt = time.Now()
	}
	maxExpiry := claims.IssuedAt.Add(MaxSessionAccessTokenTTL)
	if claims.ExpiresAt.IsZero() || claims.ExpiresAt.After(maxExpiry) {
		claims.ExpiresAt = maxExpiry
	}

	payload := sessionAccessJWTClaims{
		TokenUse:          sessionTokenUse,
		Email:             strings.TrimSpace(claims.Email),
		PreferredUsername: strings.TrimSpace(claims.PreferredUsername),
		Name:              strings.TrimSpace(claims.Name),
		Picture:           strings.TrimSpace(claims.Picture),
		RegisteredClaims: jwt.RegisteredClaims{
			Subject: claims.UserID.String(),
			Issuer:  s.issuer,
			Audience: jwt.ClaimStrings{
				sessionAudienceGatewayServices,
				sessionAudienceAuthnAccount,
			},
			IssuedAt:  jwt.NewNumericDate(claims.IssuedAt),
			ExpiresAt: jwt.NewNumericDate(claims.ExpiresAt),
		},
	}
	if claims.JTI != uuid.Nil {
		payload.ID = claims.JTI.String()
	}

	return s.signClaims(ctx, payload, sessionAccessTokenTyp)
}

// VerifySessionAccessToken checks the signature, header typ, token_use, and
// registered claims of raw and returns the embedded session access claims.
// OIDC provider tokens (typ "JWT") are rejected with ErrInvalidToken.
func (v *Verifier) VerifySessionAccessToken(
	ctx context.Context,
	raw string,
	requiredAudience string,
) (SessionAccessTokenClaims, error) {
	if v == nil || v.signing == nil {
		return SessionAccessTokenClaims{}, signature.ErrInvalidConfig
	}
	requiredAudience = strings.TrimSpace(requiredAudience)
	if requiredAudience == "" {
		return SessionAccessTokenClaims{}, signature.ErrInvalidConfig
	}

	var payload sessionAccessJWTClaims
	token, parts, err := jwt.NewParser().ParseUnverified(strings.TrimSpace(raw), &payload)
	if err != nil {
		return SessionAccessTokenClaims{}, errors.Join(ErrInvalidToken, err)
	}

	alg, _ := token.Header["alg"].(string)
	if alg != signature.AlgorithmRS256 {
		return SessionAccessTokenClaims{}, ErrInvalidToken
	}
	kid, _ := token.Header["kid"].(string)
	if strings.TrimSpace(kid) == "" {
		return SessionAccessTokenClaims{}, ErrInvalidToken
	}
	typ, _ := token.Header["typ"].(string)
	if typ != sessionAccessTokenTyp {
		return SessionAccessTokenClaims{}, ErrInvalidToken
	}

	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return SessionAccessTokenClaims{}, errors.Join(ErrInvalidToken, err)
	}
	valid, err := v.signing.Verify(ctx, []byte(parts[0]+"."+parts[1]), signature.Signature{
		KeyID:     kid,
		Alg:       signature.AlgorithmRS256,
		Signature: sigBytes,
	})
	if err != nil {
		return SessionAccessTokenClaims{}, err
	}
	if !valid {
		return SessionAccessTokenClaims{}, ErrInvalidToken
	}

	return validateSessionAccessClaims(v.issuer, requiredAudience, payload)
}

func validateSessionAccessClaims(
	issuer string,
	requiredAudience string,
	payload sessionAccessJWTClaims,
) (SessionAccessTokenClaims, error) {
	if payload.TokenUse != sessionTokenUse {
		return SessionAccessTokenClaims{}, ErrInvalidToken
	}
	if payload.Issuer != issuer {
		return SessionAccessTokenClaims{}, ErrInvalidToken
	}
	if !hasAudience(payload.Audience, requiredAudience) {
		return SessionAccessTokenClaims{}, ErrInvalidToken
	}
	if payload.ExpiresAt == nil || payload.IssuedAt == nil {
		return SessionAccessTokenClaims{}, ErrInvalidToken
	}

	now := time.Now()
	if now.After(payload.ExpiresAt.Time.Add(clockSkewLeeway)) {
		return SessionAccessTokenClaims{}, ErrExpiredToken
	}
	if payload.IssuedAt.Time.After(now.Add(clockSkewLeeway)) {
		return SessionAccessTokenClaims{}, ErrInvalidToken
	}

	userID, err := uuid.Parse(payload.Subject)
	if err != nil {
		return SessionAccessTokenClaims{}, errors.Join(ErrInvalidToken, err)
	}

	claims := SessionAccessTokenClaims{
		UserID:            userID,
		Email:             payload.Email,
		PreferredUsername: payload.PreferredUsername,
		Name:              payload.Name,
		Picture:           payload.Picture,
		IssuedAt:          payload.IssuedAt.Time,
		ExpiresAt:         payload.ExpiresAt.Time,
	}
	if jti, parseErr := uuid.Parse(payload.ID); parseErr == nil {
		claims.JTI = jti
	}
	return claims, nil
}

func hasAudience(audiences jwt.ClaimStrings, required string) bool {
	for _, audience := range audiences {
		if audience == required {
			return true
		}
	}
	return false
}
