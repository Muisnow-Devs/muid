package oidc

import (
	"context"
	"errors"
	"slices"

	"github.com/google/uuid"

	"sanzi.io/muid/internal/oidctoken"
)

// UserInfoResult is the OIDC userinfo response; pointer fields are
// scope-gated and sourced from the profile service.
type UserInfoResult struct {
	Subject           uuid.UUID
	Name              *string
	Picture           *string
	PreferredUsername *string
	Locale            *string
	Zoneinfo          *string
	Email             *string
	EmailVerified     *bool
}

// UserInfo verifies the access token locally and returns the claims allowed
// by its scopes. RFC 6750 failures are returned as *OAuthError
// (invalid_token / insufficient_scope).
func (p *Provider) UserInfo(ctx context.Context, accessToken string) (UserInfoResult, error) {
	claims, err := p.verifier.VerifyAccessToken(ctx, accessToken)
	if errors.Is(err, oidctoken.ErrInvalidToken) || errors.Is(err, oidctoken.ErrExpiredToken) {
		return UserInfoResult{}, oauthError(
			ErrCodeInvalidToken,
			"access token is invalid or expired",
		)
	}
	if err != nil {
		return UserInfoResult{}, err
	}
	if !slices.Contains(claims.Scopes, ScopeOpenID) {
		return UserInfoResult{}, oauthError(ErrCodeInsufficientScope, "openid scope required")
	}

	result := UserInfoResult{Subject: claims.UserID}

	idClaims := oidctoken.IDTokenClaims{}
	p.fillIdentityClaims(ctx, &idClaims, claims.UserID, claims.Scopes)
	if slices.Contains(claims.Scopes, ScopeProfile) {
		if idClaims.Name != "" {
			result.Name = &idClaims.Name
		}
		if idClaims.Picture != "" {
			result.Picture = &idClaims.Picture
		}
		if idClaims.PreferredUsername != "" {
			result.PreferredUsername = &idClaims.PreferredUsername
		}
		if idClaims.Locale != "" {
			result.Locale = &idClaims.Locale
		}
		if idClaims.Zoneinfo != "" {
			result.Zoneinfo = &idClaims.Zoneinfo
		}
	}
	if slices.Contains(claims.Scopes, ScopeEmail) && idClaims.Email != "" {
		result.Email = &idClaims.Email
		result.EmailVerified = idClaims.EmailVerified
	}

	return result, nil
}
