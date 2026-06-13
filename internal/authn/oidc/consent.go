package oidc

import (
	"context"
	"time"

	"github.com/google/uuid"

	"sanzi.io/muid/internal/authn/authnaudit"
	"sanzi.io/muid/internal/authn/ent"
	"sanzi.io/muid/internal/authn/ent/oidcclient"
	"sanzi.io/muid/internal/authn/ent/oidcgrant"
	"sanzi.io/muid/internal/authn/ent/oidcrefreshtoken"
	"sanzi.io/muid/pkg/audit"
	"sanzi.io/muid/pkg/enttx"
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
	revoked, err := enttx.Run(ctx, p.db.Tx,
		func(ctx context.Context, tx *ent.Tx) (int, error) {
			revoked, err := tx.OIDCGrant.Update().
				Where(
					oidcgrant.UserID(userID),
					oidcgrant.ClientRefID(client.ID),
					oidcgrant.RevokedAtIsNil(),
				).
				SetRevokedAt(now).
				Save(ctx)
			if err != nil {
				return 0, err
			}

			err = tx.OIDCRefreshToken.Update().
				Where(
					oidcrefreshtoken.UserID(userID),
					oidcrefreshtoken.ClientRefID(client.ID),
					oidcrefreshtoken.RevokedAtIsNil(),
				).
				SetRevokedAt(now).
				Exec(ctx)
			if err != nil {
				return 0, err
			}

			if revoked == 0 {
				// No active consent matched; nothing to audit.
				return 0, nil
			}
			actor := userID
			err = authnaudit.Write(ctx, tx, audit.Entry{
				ActorID:      &actor,
				Action:       audit.ActionConsentRevoke,
				ResourceType: audit.ResourceConsent,
				ResourceID:   userID.String(),
				Changes:      audit.Payload(map[string]any{"client_id": clientID}),
			})
			if err != nil {
				return 0, err
			}
			return revoked, nil
		})
	if err != nil {
		return false, err
	}

	return revoked > 0, nil
}
