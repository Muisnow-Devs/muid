package oidctoken

import (
	"context"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"sanzi.io/muid/internal/signature"
)

// IDTokenClaims describes the OIDC ID token issued after a successful
// authorization. Name/Picture/Email are scope-gated by the caller: leave them
// zero when the corresponding scope was not granted.
//
// at_hash is intentionally not emitted: it is optional for the pure
// authorization-code flow, which is the only flow this provider supports.
type IDTokenClaims struct {
	UserID            uuid.UUID
	ClientID          string
	Nonce             string
	AuthTime          time.Time
	Name              string
	Picture           string
	PreferredUsername string
	Locale            string
	Zoneinfo          string
	Email             string
	EmailVerified     *bool
	IssuedAt          time.Time
	ExpiresAt         time.Time
}

type idTokenJWTClaims struct {
	AuthorizedParty   string `json:"azp,omitempty"`
	AuthTime          int64  `json:"auth_time,omitempty"`
	Nonce             string `json:"nonce,omitempty"`
	Name              string `json:"name,omitempty"`
	Picture           string `json:"picture,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	Locale            string `json:"locale,omitempty"`
	Zoneinfo          string `json:"zoneinfo,omitempty"`
	Email             string `json:"email,omitempty"`
	EmailVerified     *bool  `json:"email_verified,omitempty"`
	jwt.RegisteredClaims
}

func (s *Signer) CreateIDToken(ctx context.Context, claims IDTokenClaims) (string, error) {
	if s == nil || s.signing == nil {
		return "", signature.ErrInvalidConfig
	}
	clientID := strings.TrimSpace(claims.ClientID)
	if claims.UserID == uuid.Nil || clientID == "" {
		return "", signature.ErrSignFailed
	}

	if claims.IssuedAt.IsZero() {
		claims.IssuedAt = time.Now()
	}
	if claims.ExpiresAt.IsZero() {
		claims.ExpiresAt = claims.IssuedAt.Add(time.Hour)
	}

	payload := idTokenJWTClaims{
		AuthorizedParty:   clientID,
		Nonce:             strings.TrimSpace(claims.Nonce),
		Name:              strings.TrimSpace(claims.Name),
		Picture:           strings.TrimSpace(claims.Picture),
		PreferredUsername: strings.TrimSpace(claims.PreferredUsername),
		Locale:            strings.TrimSpace(claims.Locale),
		Zoneinfo:          strings.TrimSpace(claims.Zoneinfo),
		Email:             strings.TrimSpace(claims.Email),
		EmailVerified:     claims.EmailVerified,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   claims.UserID.String(),
			Issuer:    s.issuer,
			Audience:  jwt.ClaimStrings{clientID},
			IssuedAt:  jwt.NewNumericDate(claims.IssuedAt),
			ExpiresAt: jwt.NewNumericDate(claims.ExpiresAt),
		},
	}
	if !claims.AuthTime.IsZero() {
		payload.AuthTime = claims.AuthTime.Unix()
	}

	return s.signClaims(ctx, payload, tokenTypeJWT)
}
