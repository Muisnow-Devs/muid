// Package oidctoken mints and validates the JWTs issued by the muid OIDC
// provider (access tokens and ID tokens), backed by signature.SignatureManager.
package oidctoken

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	"sanzi.io/muid/internal/signature"
)

const tokenTypeJWT = "JWT"

type Signer struct {
	signing signature.SignatureManager
	issuer  string
}

type AccessTokenClaims struct {
	UserID    uuid.UUID
	ClientID  string
	Scopes    []string
	Audience  []string
	JTI       uuid.UUID
	IssuedAt  time.Time
	ExpiresAt time.Time
}

type accessTokenJWTClaims struct {
	ClientID string `json:"client_id"`
	Scope    string `json:"scope"`
	jwt.RegisteredClaims
}

func NewSigner(signing signature.SignatureManager, issuer string) *Signer {
	return &Signer{
		signing: signing,
		issuer:  strings.TrimSpace(issuer),
	}
}

func (s *Signer) Issuer() string {
	if s == nil {
		return ""
	}
	return s.issuer
}

func (s *Signer) CreateAccessToken(ctx context.Context, claims AccessTokenClaims) (string, error) {
	if s == nil || s.signing == nil {
		return "", signature.ErrInvalidConfig
	}
	if claims.UserID == uuid.Nil || strings.TrimSpace(claims.ClientID) == "" {
		return "", signature.ErrSignFailed
	}

	if claims.IssuedAt.IsZero() {
		claims.IssuedAt = time.Now()
	}
	if claims.ExpiresAt.IsZero() {
		claims.ExpiresAt = claims.IssuedAt.Add(time.Hour)
	}

	payload, err := jwtPayload(s.issuer, claims)
	if err != nil {
		return "", errors.Join(signature.ErrSignFailed, err)
	}

	return s.signClaims(ctx, payload)
}

// signClaims signs payload as an RS256 JWT. The token is signed twice: the
// first pass learns the active key id so it can be embedded in the header.
func (s *Signer) signClaims(ctx context.Context, payload jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, payload)
	token.Header["typ"] = tokenTypeJWT

	signingInput, err := token.SigningString()
	if err != nil {
		return "", errors.Join(signature.ErrSignFailed, err)
	}
	sig, err := s.signing.Sign(ctx, []byte(signingInput))
	if err != nil {
		return "", err
	}

	token.Header["kid"] = sig.KeyID
	signingInput, err = token.SigningString()
	if err != nil {
		return "", errors.Join(signature.ErrSignFailed, err)
	}

	sig, err = s.signing.Sign(ctx, []byte(signingInput))
	if err != nil {
		return "", err
	}

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig.Signature), nil
}

func jwtPayload(issuer string, claims AccessTokenClaims) (accessTokenJWTClaims, error) {
	issued := timestamppb.New(claims.IssuedAt)
	expires := timestamppb.New(claims.ExpiresAt)
	if err := issued.CheckValid(); err != nil {
		return accessTokenJWTClaims{}, err
	}
	if err := expires.CheckValid(); err != nil {
		return accessTokenJWTClaims{}, err
	}

	payload := accessTokenJWTClaims{
		ClientID: strings.TrimSpace(claims.ClientID),
		Scope:    strings.Join(trimValues(claims.Scopes), " "),
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   claims.UserID.String(),
			Issuer:    issuer,
			IssuedAt:  jwt.NewNumericDate(claims.IssuedAt),
			ExpiresAt: jwt.NewNumericDate(claims.ExpiresAt),
		},
	}
	if claims.JTI != uuid.Nil {
		payload.ID = claims.JTI.String()
	}
	audience := trimValues(claims.Audience)
	if len(audience) > 0 {
		payload.Audience = jwt.ClaimStrings(audience)
	}
	return payload, nil
}

func trimValues(in []string) []string {
	out := make([]string, 0, len(in))
	for _, value := range in {
		value = strings.TrimSpace(value)
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}
