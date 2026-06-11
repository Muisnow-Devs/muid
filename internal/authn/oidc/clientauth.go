// Package oidc implements the OIDC provider domain logic for authn:
// authorization, consent, token issuance, device flow, and client
// administration.
package oidc

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"time"

	"sanzi.io/muid/internal/authn/ent"
	"sanzi.io/muid/internal/authn/ent/oidcclient"
	"sanzi.io/muid/internal/authn/ent/oidcclientsecret"
	"sanzi.io/muid/pkg/log"
)

var (
	// ErrClientAuthFailed maps to invalid_client.
	ErrClientAuthFailed = errors.New("oidc: client authentication failed")
	// ErrAuthMethodUnsupported maps to invalid_client; private_key_jwt is
	// registered but not implemented yet.
	ErrAuthMethodUnsupported = errors.New("oidc: token endpoint auth method unsupported")
	// ErrConfidentialClientRequired maps to invalid_client; the operation is
	// limited to confidential clients (e.g. introspection).
	ErrConfidentialClientRequired = errors.New("oidc: confidential client required")
)

// AuthenticateClient verifies the in-message client credentials against the
// client's registered token_endpoint_auth_method. The gateway normalizes
// Basic-auth and form-post credentials into the same secret field, so basic
// and post are equivalent here.
func AuthenticateClient(
	ctx context.Context,
	db *ent.Client,
	client *ent.OIDCClient,
	secret string,
) error {
	switch client.TokenEndpointAuthMethod {
	case oidcclient.TokenEndpointAuthMethodNone:
		if secret != "" {
			return ErrClientAuthFailed
		}
		return nil
	case oidcclient.TokenEndpointAuthMethodClientSecretBasic,
		oidcclient.TokenEndpointAuthMethodClientSecretPost:
		return verifyClientSecret(ctx, db, client, secret)
	case oidcclient.TokenEndpointAuthMethodPrivateKeyJwt:
		return ErrAuthMethodUnsupported
	default:
		return ErrClientAuthFailed
	}
}

// RequireConfidentialClient authenticates and additionally rejects public
// clients.
func RequireConfidentialClient(
	ctx context.Context,
	db *ent.Client,
	client *ent.OIDCClient,
	secret string,
) error {
	if client.TokenEndpointAuthMethod == oidcclient.TokenEndpointAuthMethodNone {
		return ErrConfidentialClientRequired
	}
	return AuthenticateClient(ctx, db, client, secret)
}

func verifyClientSecret(
	ctx context.Context,
	db *ent.Client,
	client *ent.OIDCClient,
	secret string,
) error {
	if secret == "" {
		return ErrClientAuthFailed
	}

	hash := HashClientSecret(secret)
	row, err := db.OIDCClientSecret.Query().
		Where(
			oidcclientsecret.ClientRefID(client.ID),
			oidcclientsecret.SecretHash(hash),
			oidcclientsecret.RevokedAtIsNil(),
		).
		Only(ctx)
	if ent.IsNotFound(err) {
		return ErrClientAuthFailed
	}
	if err != nil {
		return err
	}

	now := time.Now()
	if row.ExpiresAt != nil && now.After(*row.ExpiresAt) {
		return ErrClientAuthFailed
	}
	if subtle.ConstantTimeCompare(row.SecretHash, hash) != 1 {
		return ErrClientAuthFailed
	}

	err = db.OIDCClientSecret.UpdateOneID(row.ID).SetLastUsedAt(now).Exec(ctx)
	if err != nil {
		// Best-effort bookkeeping; authentication already succeeded.
		log.LogUnexpected(ctx, "oidc client secret last_used_at", err.Error())
	}
	return nil
}

// HashClientSecret is the storage hash for client secrets (sha256, matching
// the 32-byte secret_hash column).
func HashClientSecret(secret string) []byte {
	hash := sha256.Sum256([]byte(secret))
	return hash[:]
}
