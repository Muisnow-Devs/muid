package token

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

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
	IssuedAt  time.Time
	ExpiresAt time.Time
}

func NewSigner(signing signature.SignatureManager, issuer string) *Signer {
	return &Signer{
		signing: signing,
		issuer:  strings.TrimSpace(issuer),
	}
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

	signingInput := encodedJWTPart(
		jwtHeader(signature.AlgorithmRS256),
	) + "." + encodedJWTPart(
		payload,
	)
	sig, err := s.signing.Sign(ctx, []byte(signingInput))
	if err != nil {
		return "", err
	}

	header := jwtHeader(sig.Alg)
	header["kid"] = sig.KeyID
	signingInput = encodedJWTPart(header) + "." + encodedJWTPart(payload)

	sig, err = s.signing.Sign(ctx, []byte(signingInput))
	if err != nil {
		return "", err
	}

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig.Signature), nil
}

func jwtHeader(alg string) map[string]string {
	return map[string]string{
		"alg": alg,
		"typ": tokenTypeJWT,
	}
}

func jwtPayload(issuer string, claims AccessTokenClaims) (map[string]any, error) {
	issued := timestamppb.New(claims.IssuedAt)
	expires := timestamppb.New(claims.ExpiresAt)
	if err := issued.CheckValid(); err != nil {
		return nil, err
	}
	if err := expires.CheckValid(); err != nil {
		return nil, err
	}

	payload := map[string]any{
		"sub":       claims.UserID.String(),
		"client_id": strings.TrimSpace(claims.ClientID),
		"scope":     strings.Join(trimScopes(claims.Scopes), " "),
		"iat":       claims.IssuedAt.Unix(),
		"exp":       claims.ExpiresAt.Unix(),
	}
	if issuer != "" {
		payload["iss"] = issuer
	}
	if len(claims.Audience) == 1 {
		payload["aud"] = claims.Audience[0]
	}
	if len(claims.Audience) > 1 {
		payload["aud"] = trimScopes(claims.Audience)
	}
	return payload, nil
}

func encodedJWTPart(value any) string {
	payload, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(payload)
}

func trimScopes(in []string) []string {
	out := make([]string, 0, len(in))
	for _, value := range in {
		value = strings.TrimSpace(value)
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}
