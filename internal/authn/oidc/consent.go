package oidc

import (
	"context"
	"time"

	"github.com/google/uuid"

	"sanzi.io/muid/internal/authn/ent"
	"sanzi.io/muid/internal/authn/ent/oidcclient"
	"sanzi.io/muid/internal/authn/ent/oidcgrant"
	"sanzi.io/muid/internal/authn/ent/oidcrefreshtoken"
)

// GrantedConsent is one row of the user's consent overview.
type GrantedConsent struct {
	ClientID     string
	ClientName   string
	Scopes       []string
	AuthorizedAt time.Time
	LastUsedAt   time.Time
}

// ListGrantedConsents returns the user's active consents.
func (p *Provider) ListGrantedConsents(
	ctx context.Context,
	userID uuid.UUID,
) ([]GrantedConsent, error) {
	grants, err := p.db.OIDCGrant.Query().
		Where(oidcgrant.UserID(userID), oidcgrant.RevokedAtIsNil()).
		WithClient().
		All(ctx)
	if err != nil {
		return nil, err
	}

	out := make([]GrantedConsent, 0, len(grants))
	for _, grant := range grants {
		client := grant.Edges.Client
		if client == nil || client.DeletedAt != nil {
			continue
		}
		out = append(out, GrantedConsent{
			ClientID:     client.ClientID,
			ClientName:   client.ClientName,
			Scopes:       grant.Scopes,
			AuthorizedAt: grant.AuthorizedAt,
			LastUsedAt:   grant.LastUsedAt,
		})
	}
	return out, nil
}

// RevokeConsent revokes the user's consent for the client and all of the
// user's refresh-token families issued to it. Access tokens already in the
// wild expire on their own (stateless JWTs).
func (p *Provider) RevokeConsent(
	ctx context.Context,
	userID uuid.UUID,
	clientID string,
) (bool, error) {
	client, err := p.db.OIDCClient.Query().
		Where(oidcclient.ClientID(clientID)).
		Only(ctx)
	if ent.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	now := time.Now()
	revoked, err := p.db.OIDCGrant.Update().
		Where(
			oidcgrant.UserID(userID),
			oidcgrant.ClientRefID(client.ID),
			oidcgrant.RevokedAtIsNil(),
		).
		SetRevokedAt(now).
		Save(ctx)
	if err != nil {
		return false, err
	}

	err = p.db.OIDCRefreshToken.Update().
		Where(
			oidcrefreshtoken.UserID(userID),
			oidcrefreshtoken.ClientRefID(client.ID),
			oidcrefreshtoken.RevokedAtIsNil(),
		).
		SetRevokedAt(now).
		Exec(ctx)
	if err != nil {
		return false, err
	}

	return revoked > 0, nil
}
