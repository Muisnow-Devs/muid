package identity

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	pbSession "sanzi.io/muid/api/proto/authn/v1/session"
	"sanzi.io/muid/internal/authn/ent"
	"sanzi.io/muid/internal/authn/ent/userfederatedidentity"
	"sanzi.io/muid/internal/identity"
	"sanzi.io/muid/internal/session"
)

const (
	GOOGLE_OIDC_PROVIDER_URL   = "https://accounts.google.com"
	GITHUB_OIDC_PROVIDER_URL   = "https://token.actions.githubusercontent.com"
	FACEBOOK_OIDC_PROVIDER_URL = "https://www.facebook.com"
)

type OIDCIdentityProvider struct {
	transitionStore session.AuthTransitionStore
	db              *ent.Client

	providerName string
	provider     *oidc.Provider
	oauth2Config *oauth2.Config
	verifier     *oidc.IDTokenVerifier
}

type OIDCClaims struct {
	FederatedIdentity string `json:"sub"`
	Name              string `json:"name"`
	Picture           string `json:"picture"`
	Email             string `json:"email"`
	EmailVerified     bool   `json:"email_verified"`
}

type OIDCProviderConfig struct {
	Name         string
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
}

func NewOIDCProvider(
	ctx context.Context,
	config OIDCProviderConfig,
	transitionStore session.AuthTransitionStore,
	db *ent.Client,
) (identity.IdentityProvider, error) {
	provider, err := oidc.NewProvider(ctx, config.Issuer)
	if err != nil {
		return nil, err
	}

	oauth2Config := &oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  config.RedirectURL,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: config.ClientID})

	return &OIDCIdentityProvider{
		providerName:    config.Name,
		provider:        provider,
		oauth2Config:    oauth2Config,
		verifier:        verifier,
		transitionStore: transitionStore,
		db:              db,
	}, nil
}

func (p *OIDCIdentityProvider) Name() string {
	return p.providerName
}

func generateRandomState() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (p *OIDCIdentityProvider) Start(
	ctx context.Context,
	input identity.StartInput,
) (identity.StepResult, error) {
	// Generate a secure random state for OIDC flow
	state := generateRandomState()

	store := session.SessionStore{
		State: state,
		Step:  "start",
	}

	sess, err := p.transitionStore.Create(ctx, p.providerName, store)
	if err != nil {
		return identity.StepResult{}, errors.Join(identity.ErrInternal, err)
	}

	authURL := p.oauth2Config.AuthCodeURL(state, oidc.Nonce(generateRandomState()))

	return identity.StepResult{
		TransitionId: sess.Id,
		Type:         identity.StepRedirect,
		RedirectURL:  authURL,
	}, nil
}

func (p *OIDCIdentityProvider) Continue(
	ctx context.Context,
	input identity.ContinueInput,
) (identity.StepResult, error) {
	code, ok := input.Payload["code"].(string)
	if !ok {
		return identity.StepResult{}, errors.Join(
			identity.ErrInvalidInput,
			errors.New("missing code in payload"),
		)
	}

	state, ok := input.Payload["state"].(string)
	if !ok {
		return identity.StepResult{}, errors.Join(
			identity.ErrInvalidInput,
			errors.New("missing state in payload"),
		)
	}

	// Verify state against the stored transition session
	sess, err := p.transitionStore.Get(ctx, input.TransitionId)
	if err != nil {
		return identity.StepResult{}, errors.Join(identity.ErrSessionNotFound, err)
	}

	if sess.Store.State != state {
		return identity.StepResult{}, errors.Join(
			identity.ErrInvalidSessionState,
			errors.New("state mismatch (CSRF prevention)"),
		)
	}

	token, err := p.oauth2Config.Exchange(ctx, code)
	if err != nil {
		return identity.StepResult{}, errors.Join(identity.ErrAuthenticationFailed, err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return identity.StepResult{}, errors.Join(
			identity.ErrAuthenticationFailed,
			errors.New("no id_token field in oauth2 token"),
		)
	}

	idToken, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return identity.StepResult{}, errors.Join(identity.ErrAuthenticationFailed, err)
	}

	var claims OIDCClaims
	if err := idToken.Claims(&claims); err != nil {
		return identity.StepResult{}, errors.Join(identity.ErrAuthenticationFailed, err)
	}

	fedId, err := p.db.UserFederatedIdentity.Query().
		Where(
			userfederatedidentity.ProviderEQ(p.providerName),
			userfederatedidentity.SubjectEQ(claims.FederatedIdentity),
		).
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			// TODO: Add placeholder for creating a new account using the Claims
			// For example, redirect the user to a profile creation page or
			// automatically provision an account here.

			return identity.StepResult{
				Type: identity.StepChallenge,
				Challenge: map[string]interface{}{
					"action": "create_account",
					"claims": claims,
				},
			}, nil
		}
		return identity.StepResult{}, errors.Join(identity.ErrInternal, err)
	}

	// Returns the authenticated state if login is successful
	return identity.StepResult{
		Type: identity.StepComplete,
		AuthenticatedResult: &pbSession.AuthenticatedResult{
			UserId:    fedId.UserID.String(),
			AuthLevel: pbSession.AuthLevel_AUTH_LEVEL_MEDIUM, // Assumed level for OIDC
		},
	}, nil
}
