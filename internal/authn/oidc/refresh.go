package oidc

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"

	"sanzi.io/muid/internal/authn/ent"
	"sanzi.io/muid/internal/authn/ent/oidcrefreshtoken"
	"sanzi.io/muid/internal/authn/oidc/policy"
	"sanzi.io/muid/pkg/enttx"
	"sanzi.io/muid/pkg/log"
)

// Refresh token wire format mirrors first-party sessions: selector.validator
// where the selector is the DB lookup key and only a hash of the validator is
// stored (12 bytes -> 16 chars, 32 bytes -> 43 chars, both raw-base64url).
const (
	refreshSelectorBytes  = 12
	refreshValidatorBytes = 32
)

var errInvalidRefreshGrant = oauthError(ErrCodeInvalidGrant, "invalid refresh token")

// issueRefreshToken creates a refresh-token row and returns its wire token.
// A nil familyID starts a new rotation family rooted at the new row.
func issueRefreshToken(
	ctx context.Context,
	create *ent.OIDCRefreshTokenClient,
	userID, clientRefID uuid.UUID,
	scopes []string,
	familyID *uuid.UUID,
	parentID *uuid.UUID,
) (string, error) {
	selector, err := randomToken(refreshSelectorBytes)
	if err != nil {
		return "", err
	}
	validator, err := randomToken(refreshValidatorBytes)
	if err != nil {
		return "", err
	}
	validationHash := sha256.Sum256([]byte(validator))

	id, err := uuid.NewV7()
	if err != nil {
		return "", err
	}
	family := id
	if familyID != nil {
		family = *familyID
	}

	builder := create.Create().
		SetID(id).
		SetUserID(userID).
		SetClientRefID(clientRefID).
		SetScopes(scopes).
		SetSelector(selector).
		SetValidationHash(validationHash[:]).
		SetFamilyID(family)
	if parentID != nil {
		builder.SetParentID(*parentID)
	}

	err = builder.Exec(ctx)
	if err != nil {
		return "", err
	}
	return selector + "." + validator, nil
}

func splitRefreshWire(wire string) (selector, validator string, ok bool) {
	selector, validator, found := strings.Cut(strings.TrimSpace(wire), ".")
	if !found || selector == "" || validator == "" {
		return "", "", false
	}
	return selector, validator, true
}

// resolveRefreshToken validates the wire token and returns its row without
// consuming it. Reuse of an already-rotated or revoked token revokes the
// whole family (RFC 6819 refresh token rotation reuse detection).
func (p *Provider) resolveRefreshToken(
	ctx context.Context,
	client *ent.OIDCClient,
	wire string,
) (*ent.OIDCRefreshToken, error) {
	selector, validator, ok := splitRefreshWire(wire)
	if !ok {
		return nil, errInvalidRefreshGrant
	}

	row, err := p.db.OIDCRefreshToken.Query().
		Where(oidcrefreshtoken.Selector(selector)).
		Only(ctx)
	if ent.IsNotFound(err) {
		return nil, errInvalidRefreshGrant
	}
	if err != nil {
		return nil, err
	}

	validationHash := sha256.Sum256([]byte(validator))
	if subtle.ConstantTimeCompare(row.ValidationHash, validationHash[:]) != 1 {
		return nil, errInvalidRefreshGrant
	}
	if client != nil && row.ClientRefID != client.ID {
		return nil, errInvalidRefreshGrant
	}

	if !row.UsedAt.IsZero() || !row.RevokedAt.IsZero() {
		revokeErr := p.revokeRefreshFamily(ctx, row.FamilyID)
		if revokeErr != nil {
			log.LogUnexpected(ctx, "oidc refresh family revoke", revokeErr.Error(),
				log.UserID(row.UserID))
		}
		return nil, errInvalidRefreshGrant
	}
	if time.Now().After(row.ExpiresAt) {
		return nil, errInvalidRefreshGrant
	}
	return row, nil
}

// rotateRefreshToken exchanges a valid refresh token for fresh tokens,
// rotating the refresh token within its family.
func (p *Provider) rotateRefreshToken(
	ctx context.Context,
	client *ent.OIDCClient,
	wire string,
	requestedScopes []string,
) (TokenOutput, error) {
	row, err := p.resolveRefreshToken(ctx, client, wire)
	if err != nil {
		return TokenOutput{}, err
	}

	scopes := row.Scopes
	if len(requestedScopes) > 0 {
		if policy.ScopesAllowed(row.Scopes, requestedScopes) != nil {
			return TokenOutput{}, oauthError(
				ErrCodeInvalidScope,
				"requested scope exceeds the original grant",
			)
		}
		scopes = requestedScopes
	}

	// Access may have been revoked (org membership, allowlist, client
	// disabled) since the last refresh.
	err = p.eval.AuthorizeUser(ctx, client, row.UserID, scopes)
	if err != nil {
		if _, ok := AsOAuthError(accessPolicyError(err)); ok {
			return TokenOutput{}, oauthError(ErrCodeInvalidGrant, "access revoked")
		}
		return TokenOutput{}, err
	}

	now := time.Now()
	newWire, err := enttx.Run(ctx, p.db.Tx, func(ctx context.Context, tx *ent.Tx) (string, error) {
		claimed, claimErr := tx.OIDCRefreshToken.Update().
			Where(
				oidcrefreshtoken.ID(row.ID),
				oidcrefreshtoken.UsedAtIsNil(),
				oidcrefreshtoken.RevokedAtIsNil(),
			).
			SetUsedAt(now).
			Save(ctx)
		if claimErr != nil {
			return "", claimErr
		}
		if claimed == 0 {
			// Lost a race with another rotation of the same token: reuse.
			return "", errInvalidRefreshGrant
		}

		return issueRefreshToken(
			ctx,
			tx.OIDCRefreshToken,
			row.UserID,
			row.ClientRefID,
			row.Scopes,
			&row.FamilyID,
			&row.ID,
		)
	})
	if errors.Is(err, errInvalidRefreshGrant) {
		revokeErr := p.revokeRefreshFamily(ctx, row.FamilyID)
		if revokeErr != nil {
			log.LogUnexpected(ctx, "oidc refresh family revoke", revokeErr.Error(),
				log.UserID(row.UserID))
		}
		return TokenOutput{}, errInvalidRefreshGrant
	}
	if err != nil {
		return TokenOutput{}, err
	}

	out, err := p.mintAccessToken(ctx, client, row.UserID, scopes)
	if err != nil {
		return TokenOutput{}, err
	}
	out.RefreshToken = newWire
	return out, nil
}

// revokeRefreshFamily revokes every live token in a rotation family.
func (p *Provider) revokeRefreshFamily(ctx context.Context, familyID uuid.UUID) error {
	return p.db.OIDCRefreshToken.Update().
		Where(
			oidcrefreshtoken.FamilyID(familyID),
			oidcrefreshtoken.RevokedAtIsNil(),
		).
		SetRevokedAt(time.Now()).
		Exec(ctx)
}
