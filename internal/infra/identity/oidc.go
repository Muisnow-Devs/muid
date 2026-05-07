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
	Subject string `json:"sub"`
	Name    string `json:"name"`
	Picture string `json:"picture"`

	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
}

type OIDCProviderConfig struct {
	Name         string
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
}

func (*OIDCIdentityProvider) generateRandomState() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
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

func (p *OIDCIdentityProvider) Start(
	ctx context.Context,
	input identity.StartInput,
) (identity.StepResult, error) {
	// Generate a secure random state for OIDC flow
	state := p.generateRandomState()
	verifier := oauth2.GenerateVerifier()

	store := session.SessionStore{
		State:        state,
		Step:         "start",
		CodeVerifier: verifier,
	}

	sess, err := p.transitionStore.Create(ctx, p.providerName, store)
	if err != nil {
		return identity.StepResult{}, err
	}

	authURL := p.oauth2Config.AuthCodeURL(
		state,
		oidc.Nonce(p.generateRandomState()),
		oauth2.S256ChallengeOption(verifier),
	)

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
	req, err := p.parseContinuePayload(input.Payload)
	if err != nil {
		return identity.StepResult{}, err
	}

	sess, err := p.validateTransition(ctx, input.TransitionId, req.State)
	if err != nil {
		return identity.StepResult{}, err
	}

	claims, err := p.exchangeAndVerify(
		ctx,
		req.Code,
		sess.Store.CodeVerifier,
	)
	if err != nil {
		return identity.StepResult{}, err
	}

	userID, err := p.findOrCreateUser(ctx, claims)
	if err != nil {
		return identity.StepResult{}, errors.Join(
			identity.ErrAuthenticationFailed,
			err,
		)
	}

	_ = p.transitionStore.Delete(ctx, sess.Id)
	return p.completedResult(userID), nil
}

type continueRequest struct {
	Code  string
	State string
}

func (*OIDCIdentityProvider) parseContinuePayload(payload map[string]any) (continueRequest, error) {
	code, ok := payload["code"].(string)
	if !ok || code == "" {
		return continueRequest{}, errors.Join(
			identity.ErrInvalidInput,
			errors.New("missing code"),
		)
	}

	state, ok := payload["state"].(string)
	if !ok || state == "" {
		return continueRequest{}, errors.Join(
			identity.ErrInvalidInput,
			errors.New("missing state"),
		)
	}

	return continueRequest{
		Code:  code,
		State: state,
	}, nil
}

func (p *OIDCIdentityProvider) validateTransition(
	ctx context.Context,
	transitionID string,
	state string,
) (session.AuthSession, error) {
	sess, err := p.transitionStore.Get(ctx, transitionID)
	if err != nil {
		return session.AuthSession{}, errors.Join(
			identity.ErrSessionNotFound,
			err,
		)
	}

	if sess.Store.State != state {
		return session.AuthSession{}, errors.Join(
			identity.ErrInvalidSessionState,
			errors.New("state mismatch"),
		)
	}

	return sess, nil
}

func (p *OIDCIdentityProvider) exchangeAndVerify(
	ctx context.Context,
	code string,
	verifier string,
) (OIDCClaims, error) {
	token, err := p.exchangeCode(ctx, code, verifier)
	if err != nil {
		return OIDCClaims{}, err
	}

	idToken, err := p.extractIDToken(token)
	if err != nil {
		return OIDCClaims{}, err
	}

	return p.verifyIDToken(ctx, idToken)
}

func (p *OIDCIdentityProvider) exchangeCode(
	ctx context.Context,
	code string,
	verifier string,
) (*oauth2.Token, error) {
	return p.oauth2Config.Exchange(
		ctx,
		code,
		oauth2.VerifierOption(verifier),
	)
}

func (*OIDCIdentityProvider) extractIDToken(token *oauth2.Token) (string, error) {
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return "", errors.New("no id_token field in oauth2 token")
	}
	return rawIDToken, nil
}

func (p *OIDCIdentityProvider) verifyIDToken(
	ctx context.Context,
	rawIDToken string,
) (OIDCClaims, error) {
	idToken, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return OIDCClaims{}, err
	}

	var claims OIDCClaims
	if err := idToken.Claims(&claims); err != nil {
		return OIDCClaims{}, err
	}

	return claims, nil
}

func (p *OIDCIdentityProvider) findOrCreateUser(
	ctx context.Context,
	claims OIDCClaims,
) (string, error) {
	fedUser, err := p.db.UserFederatedIdentity.Query().
		Where(
			userfederatedidentity.ProviderEQ(p.providerName),
			userfederatedidentity.SubjectEQ(claims.Subject),
		).
		Only(ctx)

	if ent.IsNotFound(err) {
		//  TODO: Create a new account or link to an existing account based on the claims.
		//        Maybe replace fedId if user created and linked to the federated identity
		//        in the same request?

		panic("unimplemented: account provisioning and linking logic for OIDC identities")
	} else if err != nil {
		return "", err
	}

	return fedUser.UserID.String(), nil
}

func (*OIDCIdentityProvider) completedResult(userID string) identity.StepResult {
	return identity.StepResult{
		Type: identity.StepComplete,
		AuthenticatedResult: &pbSession.AuthenticatedResult{
			UserId:    userID,
			AuthLevel: pbSession.AuthLevel_AUTH_LEVEL_MEDIUM,
		},
	}
}
