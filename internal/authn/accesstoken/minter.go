// Package accesstoken mints the short-lived JWT session access tokens
// returned alongside opaque session tokens. The opaque session token remains
// the only credential authn accepts; the JWT is verified by gateways/CDN
// locally via JWKS.
package accesstoken

import (
	"context"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	sessionpb "sanzi.io/muid/api/proto/authn/v1/session"
	profilepb "sanzi.io/muid/api/proto/profile/v1"
	"sanzi.io/muid/internal/oidctoken"
	"sanzi.io/muid/pkg/log"
)

// Minter exchanges a resolved session for a short-lived session access token.
type Minter struct {
	signer         *oidctoken.Signer
	profile        profilepb.ProfileServiceClient // nil tolerated: claims degrade
	profileTimeout time.Duration
	ttl            time.Duration
}

// NewMinter builds a Minter. ttl is clamped to
// (0, oidctoken.MaxSessionAccessTokenTTL].
func NewMinter(
	signer *oidctoken.Signer,
	profile profilepb.ProfileServiceClient,
	profileTimeout time.Duration,
	ttl time.Duration,
) *Minter {
	if ttl <= 0 || ttl > oidctoken.MaxSessionAccessTokenTTL {
		ttl = oidctoken.MaxSessionAccessTokenTTL
	}
	return &Minter{
		signer:         signer,
		profile:        profile,
		profileTimeout: profileTimeout,
		ttl:            ttl,
	}
}

// MintInput identifies the session principal the token is minted for.
type MintInput struct {
	UserID uuid.UUID
	// FallbackEmail fills the email claim when the profile service does not
	// supply one; may be empty.
	FallbackEmail string
}

// Mint signs a fresh session access token. Profile claims are best-effort:
// a failed profile lookup is logged and the token is minted with degraded
// claims rather than failing.
func (m *Minter) Mint(ctx context.Context, in MintInput) (*sessionpb.AccessToken, error) {
	now := time.Now()
	claims := oidctoken.SessionAccessTokenClaims{
		UserID:    in.UserID,
		Email:     in.FallbackEmail,
		IssuedAt:  now,
		ExpiresAt: now.Add(m.ttl),
	}
	if jti, err := uuid.NewV7(); err == nil {
		claims.JTI = jti
	}

	if profile := m.fetchProfile(ctx, in.UserID); profile != nil {
		claims.Name = profile.GetDisplayName()
		claims.Picture = profile.GetAvatarUrl()
		claims.PreferredUsername = profile.GetUsername()
		if email := profile.GetEmail(); email != "" {
			claims.Email = email
		}
	}

	value, err := m.signer.CreateSessionAccessToken(ctx, claims)
	if err != nil {
		return nil, err
	}

	out := &sessionpb.AccessToken{}
	out.SetValue(value)
	out.SetIssuedAt(timestamppb.New(claims.IssuedAt))
	out.SetExpiresAt(timestamppb.New(claims.ExpiresAt))
	return out, nil
}

// fetchProfile best-effort loads the user's profile; nil when the profile
// service is not wired or the call fails.
func (m *Minter) fetchProfile(
	ctx context.Context,
	userID uuid.UUID,
) *profilepb.GetProfileResponse {
	if m.profile == nil {
		return nil
	}

	if m.profileTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, m.profileTimeout)
		defer cancel()
	}

	req := &profilepb.GetProfileRequest{}
	req.SetId(userID.String())
	resp, err := m.profile.GetProfile(ctx, req)
	if err != nil {
		log.LogUnexpected(ctx, "session access token profile claims", err.Error(),
			log.UserID(userID))
		return nil
	}
	return resp
}
