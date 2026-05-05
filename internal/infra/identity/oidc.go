package identity

import (
	"context"
	"fmt"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
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
	}, nil
}

func (p *OIDCIdentityProvider) Name() string {
	return p.providerName
}

func (p *OIDCIdentityProvider) Start(ctx context.Context, input identity.StartInput) (identity.StepResult, error) {
	return identity.StepResult{
		Token:     p.oauth2Config.AuthCodeURL(input.State),
		State:     input.State,
		Redirect:  p.oauth2Config.AuthCodeURL(input.State),
		CreatedAt: time.Now().Unix(),
	}, nil
}

func (p *OIDCIdentityProvider) Continue(ctx context.Context, input identity.ContinueInput) (identity.StepResult, error) {
	token, err := p.oauth2Config.Exchange(ctx, input.Code)
	if err != nil {
		return identity.StepResult{}, err
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return identity.StepResult{}, fmt.Errorf("no id_token field in oauth2 token")
	}

	idToken, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return identity.StepResult{}, err
	}

	var claims OIDCClaims
	if err := idToken.Claims(&claims); err != nil {
		return identity.StepResult{}, err
	}

	// TODO: Store the id reference in profile service and return signed session token instead of federated identity
	return identity.StepResult{}, nil
}
