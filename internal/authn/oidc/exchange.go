package oidc

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"time"

	"sanzi.io/muid/internal/authn/ent"
	"sanzi.io/muid/internal/authn/oidc/policy"
	"sanzi.io/muid/internal/authn/oidc/store"
)

// CodeGrantInput is the authorization_code grant.
type CodeGrantInput struct {
	Code         string
	RedirectURI  string
	CodeVerifier string
}

// RefreshGrantInput is the refresh_token grant; Scopes optionally narrows.
type RefreshGrantInput struct {
	RefreshToken string
	Scopes       []string
}

// DeviceGrantInput is the urn:ietf:params:oauth:grant-type:device_code grant.
type DeviceGrantInput struct {
	DeviceCode string
}

// ExchangeInput is one token-endpoint call; exactly one grant must be set.
type ExchangeInput struct {
	ClientID     string
	ClientSecret string

	Code    *CodeGrantInput
	Refresh *RefreshGrantInput
	Device  *DeviceGrantInput
}

// ExchangeToken implements the token endpoint for all supported grants.
// Protocol failures are returned as *OAuthError.
func (p *Provider) ExchangeToken(ctx context.Context, in ExchangeInput) (TokenOutput, error) {
	client, err := p.clientByClientID(ctx, in.ClientID)
	if errors.Is(err, ErrClientNotFound) {
		return TokenOutput{}, oauthError(ErrCodeInvalidClient, "unknown client")
	}
	if err != nil {
		return TokenOutput{}, err
	}

	err = AuthenticateClient(ctx, p.db, client, in.ClientSecret)
	if err != nil {
		return TokenOutput{}, clientAuthError(err)
	}

	switch {
	case in.Code != nil:
		return p.exchangeAuthorizationCode(ctx, client, *in.Code)
	case in.Refresh != nil:
		err = policy.GrantTypeEnabled(client, policy.GrantTypeRefreshToken)
		if err != nil {
			return TokenOutput{}, oauthError(
				ErrCodeUnauthorizedClient,
				"refresh_token grant is not enabled for this client",
			)
		}
		return p.rotateRefreshToken(ctx, client, in.Refresh.RefreshToken, in.Refresh.Scopes)
	case in.Device != nil:
		return p.redeemDeviceCode(ctx, client, in.Device.DeviceCode)
	default:
		return TokenOutput{}, oauthError(ErrCodeUnsupportedGrantType, "no grant provided")
	}
}

func clientAuthError(err error) error {
	switch {
	case errors.Is(err, ErrClientAuthFailed):
		return oauthError(ErrCodeInvalidClient, "client authentication failed")
	case errors.Is(err, ErrAuthMethodUnsupported):
		return oauthError(ErrCodeInvalidClient, "token endpoint auth method not supported")
	case errors.Is(err, ErrConfidentialClientRequired):
		return oauthError(ErrCodeInvalidClient, "confidential client required")
	default:
		return err
	}
}

func (p *Provider) exchangeAuthorizationCode(
	ctx context.Context,
	client *ent.OIDCClient,
	grant CodeGrantInput,
) (TokenOutput, error) {
	err := policy.GrantTypeEnabled(client, policy.GrantTypeAuthorizationCode)
	if err != nil {
		return TokenOutput{}, oauthError(
			ErrCodeUnauthorizedClient,
			"authorization_code grant is not enabled for this client",
		)
	}
	err = policy.ClientUsable(client)
	if err != nil {
		return TokenOutput{}, oauthError(ErrCodeUnauthorizedClient, "client is disabled")
	}

	record, err := p.codes.Consume(ctx, grant.Code)
	if errors.Is(err, store.ErrNotFound) {
		return TokenOutput{}, oauthError(
			ErrCodeInvalidGrant,
			"authorization code is invalid, expired, or already used",
		)
	}
	if err != nil {
		return TokenOutput{}, err
	}

	if record.ClientID != client.ClientID {
		return TokenOutput{}, oauthError(ErrCodeInvalidGrant, "code was issued to another client")
	}
	if record.RedirectURI != grant.RedirectURI {
		return TokenOutput{}, oauthError(ErrCodeInvalidGrant, "redirect_uri mismatch")
	}
	err = verifyPKCE(record.CodeChallenge, grant.CodeVerifier)
	if err != nil {
		return TokenOutput{}, err
	}

	return p.mintTokens(
		ctx,
		client,
		record.UserID,
		record.Scopes,
		record.Nonce,
		time.Unix(record.AuthTime, 0),
	)
}

// verifyPKCE checks S256(verifier) against the challenge stored at
// authorize-time. Codes issued without a challenge (confidential clients)
// skip verification.
func verifyPKCE(challenge, verifier string) error {
	if challenge == "" {
		return nil
	}
	if verifier == "" {
		return oauthError(ErrCodeInvalidGrant, "code_verifier is required")
	}

	digest := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(digest[:])
	if subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) != 1 {
		return oauthError(ErrCodeInvalidGrant, "code_verifier does not match")
	}
	return nil
}
