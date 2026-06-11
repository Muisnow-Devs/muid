package oidc

import (
	"context"
	"slices"
	"time"

	"github.com/google/uuid"

	profilepb "sanzi.io/muid/api/proto/profile/v1"
	"sanzi.io/muid/internal/authn/ent"
	"sanzi.io/muid/internal/authn/ent/useremail"
	"sanzi.io/muid/internal/authn/oidc/policy"
	"sanzi.io/muid/internal/authn/oidc/store"
	"sanzi.io/muid/internal/oidctoken"
	"sanzi.io/muid/pkg/log"
)

// randomToken aliases the store helper so token material across the provider
// comes from a single implementation.
var randomToken = store.RandomToken

// TokenOutput is a successful token-endpoint response.
type TokenOutput struct {
	AccessToken  string
	ExpiresIn    int64
	RefreshToken string
	IDToken      string
	Scopes       []string
}

// mintAccessToken issues the JWT access token only.
func (p *Provider) mintAccessToken(
	ctx context.Context,
	client *ent.OIDCClient,
	userID uuid.UUID,
	scopes []string,
) (TokenOutput, error) {
	jti, err := uuid.NewV7()
	if err != nil {
		return TokenOutput{}, err
	}

	now := time.Now()
	access, err := p.signer.CreateAccessToken(ctx, oidctoken.AccessTokenClaims{
		UserID:    userID,
		ClientID:  client.ClientID,
		Scopes:    scopes,
		Audience:  []string{client.ClientID},
		JTI:       jti,
		IssuedAt:  now,
		ExpiresAt: now.Add(p.cfg.AccessTokenTTL),
	})
	if err != nil {
		return TokenOutput{}, err
	}

	return TokenOutput{
		AccessToken: access,
		ExpiresIn:   int64(p.cfg.AccessTokenTTL.Seconds()),
		Scopes:      scopes,
	}, nil
}

// mintTokens issues the full token set for a fresh authorization: access
// token, ID token when the openid scope was granted, and a refresh token
// (new rotation family) when the client has the refresh_token grant enabled.
func (p *Provider) mintTokens(
	ctx context.Context,
	client *ent.OIDCClient,
	userID uuid.UUID,
	scopes []string,
	nonce string,
	authTime time.Time,
) (TokenOutput, error) {
	out, err := p.mintAccessToken(ctx, client, userID, scopes)
	if err != nil {
		return TokenOutput{}, err
	}

	if slices.Contains(scopes, ScopeOpenID) {
		now := time.Now()
		claims := oidctoken.IDTokenClaims{
			UserID:    userID,
			ClientID:  client.ClientID,
			Nonce:     nonce,
			AuthTime:  authTime,
			IssuedAt:  now,
			ExpiresAt: now.Add(p.cfg.AccessTokenTTL),
		}
		p.fillIdentityClaims(ctx, &claims, userID, scopes)

		out.IDToken, err = p.signer.CreateIDToken(ctx, claims)
		if err != nil {
			return TokenOutput{}, err
		}
	}

	if policy.GrantTypeEnabled(client, policy.GrantTypeRefreshToken) == nil {
		out.RefreshToken, err = issueRefreshToken(
			ctx,
			p.db.OIDCRefreshToken,
			userID,
			client.ID,
			scopes,
			nil,
			nil,
		)
		if err != nil {
			return TokenOutput{}, err
		}
	}

	return out, nil
}

// fillIdentityClaims adds the scope-gated identity claims. The profile
// service is the system of record for user data, so claims are read from it;
// authn's own verified-email store is only a fallback for the email claim
// when profile is unavailable. Failures are logged and tolerated: identity
// claims degrade rather than failing token issuance.
func (p *Provider) fillIdentityClaims(
	ctx context.Context,
	claims *oidctoken.IDTokenClaims,
	userID uuid.UUID,
	scopes []string,
) {
	wantProfile := slices.Contains(scopes, ScopeProfile)
	wantEmail := slices.Contains(scopes, ScopeEmail)
	if !wantProfile && !wantEmail {
		return
	}

	profile := p.fetchProfile(ctx, userID)

	if wantProfile && profile != nil {
		claims.Name = profile.GetDisplayName()
		claims.Picture = profile.GetAvatarUrl()
		claims.PreferredUsername = profile.GetUsername()
		claims.Locale = profile.GetLocale()
		claims.Zoneinfo = profile.GetTimezone()
	}

	if wantEmail {
		email := profile.GetEmail()
		if email == "" {
			fallback, _, err := p.primaryEmail(ctx, userID)
			if err != nil {
				log.LogUnexpected(ctx, "oidc email claim fallback", err.Error(),
					log.UserID(userID))
			}
			email = fallback
		}
		if email != "" {
			// Emails reach muid only through verified flows (OTP / verified
			// federated claims).
			verified := true
			claims.Email = email
			claims.EmailVerified = &verified
		}
	}
}

// fetchProfile best-effort loads the user's profile; nil when the profile
// service is not wired or the call fails.
func (p *Provider) fetchProfile(
	ctx context.Context,
	userID uuid.UUID,
) *profilepb.GetProfileResponse {
	if p.profile == nil {
		return nil
	}

	req := &profilepb.GetProfileRequest{}
	req.SetId(userID.String())
	resp, err := p.profile.GetProfile(ctx, req)
	if err != nil {
		log.LogUnexpected(ctx, "oidc profile claims", err.Error(), log.UserID(userID))
		return nil
	}
	return resp
}

// primaryEmail returns the user's primary, unrevoked email. Emails reach the
// authn store only through verified flows (OTP / verified federated claims),
// so a stored primary email is reported as verified.
func (p *Provider) primaryEmail(
	ctx context.Context,
	userID uuid.UUID,
) (string, bool, error) {
	row, err := p.db.UserEmail.Query().
		Where(
			useremail.UserID(userID),
			useremail.IsPrimary(true),
			useremail.RevokedAtIsNil(),
		).
		Only(ctx)
	if ent.IsNotFound(err) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return row.Email, true, nil
}
