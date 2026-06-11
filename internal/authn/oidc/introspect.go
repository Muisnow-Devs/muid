package oidc

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"sanzi.io/muid/internal/oidctoken"
)

// Introspection token type values (RFC 7662 token_type_hint).
const (
	TokenTypeAccessToken  = "access_token"
	TokenTypeRefreshToken = "refresh_token"
)

// Introspection is the RFC 7662 result. Only Active is meaningful when the
// token is inactive.
type Introspection struct {
	Active bool

	Scopes    []string
	ClientID  string
	TokenType string
	Subject   uuid.UUID
	Audience  []string
	Issuer    string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// IntrospectToken authenticates the calling confidential client and reports
// the state of the presented token. Unknown or invalid tokens are reported
// as inactive, never as errors.
func (p *Provider) IntrospectToken(
	ctx context.Context,
	clientID, clientSecret, token, hint string,
) (Introspection, error) {
	client, err := p.clientByClientID(ctx, clientID)
	if errors.Is(err, ErrClientNotFound) {
		return Introspection{}, oauthError(ErrCodeInvalidClient, "unknown client")
	}
	if err != nil {
		return Introspection{}, err
	}
	err = RequireConfidentialClient(ctx, p.db, client, clientSecret)
	if err != nil {
		return Introspection{}, clientAuthError(err)
	}

	// Try the hinted type first, then the other.
	if hint == TokenTypeRefreshToken {
		if result, ok := p.introspectRefreshToken(ctx, token); ok {
			return result, nil
		}
		if result, ok := p.introspectAccessToken(ctx, token); ok {
			return result, nil
		}
		return Introspection{}, nil
	}
	if result, ok := p.introspectAccessToken(ctx, token); ok {
		return result, nil
	}
	if result, ok := p.introspectRefreshToken(ctx, token); ok {
		return result, nil
	}
	return Introspection{}, nil
}

func (p *Provider) introspectAccessToken(ctx context.Context, token string) (Introspection, bool) {
	claims, err := p.verifier.VerifyAccessToken(ctx, token)
	if errors.Is(err, oidctoken.ErrExpiredToken) {
		return Introspection{}, true
	}
	if err != nil {
		return Introspection{}, false
	}

	return Introspection{
		Active:    true,
		Scopes:    claims.Scopes,
		ClientID:  claims.ClientID,
		TokenType: TokenTypeAccessToken,
		Subject:   claims.UserID,
		Audience:  claims.Audience,
		Issuer:    p.cfg.Issuer,
		IssuedAt:  claims.IssuedAt,
		ExpiresAt: claims.ExpiresAt,
	}, true
}

func (p *Provider) introspectRefreshToken(ctx context.Context, token string) (Introspection, bool) {
	// nil client: introspection reports tokens regardless of the audience
	// client (the caller is already authenticated as a confidential client).
	row, err := p.resolveRefreshToken(ctx, nil, token)
	if err != nil {
		// Invalid, expired, revoked, or reused tokens are simply inactive.
		if _, ok := AsOAuthError(err); ok {
			return Introspection{}, false
		}
		return Introspection{}, false
	}

	client, err := p.clientByRefID(ctx, row.ClientRefID)
	if err != nil {
		return Introspection{}, false
	}

	return Introspection{
		Active:    true,
		Scopes:    row.Scopes,
		ClientID:  client.ClientID,
		TokenType: TokenTypeRefreshToken,
		Subject:   row.UserID,
		Issuer:    p.cfg.Issuer,
		IssuedAt:  row.CreatedAt,
		ExpiresAt: row.ExpiresAt,
	}, true
}

// RevokeToken implements RFC 7009: refresh tokens revoke their whole
// rotation family; access tokens are stateless JWTs so revocation is a
// no-op; unknown tokens still succeed.
func (p *Provider) RevokeToken(
	ctx context.Context,
	clientID, clientSecret, token string,
) error {
	client, err := p.clientByClientID(ctx, clientID)
	if errors.Is(err, ErrClientNotFound) {
		return oauthError(ErrCodeInvalidClient, "unknown client")
	}
	if err != nil {
		return err
	}
	err = AuthenticateClient(ctx, p.db, client, clientSecret)
	if err != nil {
		return clientAuthError(err)
	}

	row, err := p.resolveRefreshToken(ctx, client, token)
	if err != nil {
		if _, ok := AsOAuthError(err); ok {
			// Not a live refresh token of this client: per spec, succeed.
			return nil
		}
		return err
	}

	return p.revokeRefreshFamily(ctx, row.FamilyID)
}
