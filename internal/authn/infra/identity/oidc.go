package identity

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"sanzi.io/muid/internal/authn/infra/account"
	idn "sanzi.io/muid/internal/identity"
	"sanzi.io/muid/internal/session"
)

const (
	GOOGLE_OIDC_PROVIDER_URL   = "https://accounts.google.com"
	GITHUB_OIDC_PROVIDER_URL   = "https://token.actions.githubusercontent.com"
	FACEBOOK_OIDC_PROVIDER_URL = "https://www.facebook.com"

	OIDCPayloadKeyCode    = "code"
	OIDCPayloadKeyState   = "state"
	OIDCTokenExtraIDToken = "id_token"
	OIDCScopeProfile      = "profile"
	OIDCScopeEmail        = "email"
)

type OIDCIdentityProvider struct {
	transitionStore session.AuthTransitionStore
	accounts        *account.Services

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
	accounts *account.Services,
) (idn.IdentityProvider, error) {
	provider, err := oidc.NewProvider(ctx, config.Issuer)
	if err != nil {
		return nil, err
	}

	oauth2Config := &oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  config.RedirectURL,
		Scopes:       []string{oidc.ScopeOpenID, OIDCScopeProfile, OIDCScopeEmail},
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: config.ClientID})

	return &OIDCIdentityProvider{
		providerName:    config.Name,
		provider:        provider,
		oauth2Config:    oauth2Config,
		verifier:        verifier,
		transitionStore: transitionStore,
		accounts:        accounts,
	}, nil
}

func (p *OIDCIdentityProvider) Name() string {
	return p.providerName
}

func (p *OIDCIdentityProvider) Start(
	ctx context.Context,
	input idn.StartInput,
) (idn.StepResult, error) {
	state := p.generateRandomState()
	verifier := oauth2.GenerateVerifier()

	store := session.SessionStore{
		Flow: session.FlowKindOIDC,
		Step: AuthStepStart,
		OIDC: &session.OIDCFlow{
			OAuthState:       state,
			PKCECodeVerifier: verifier,
		},
	}

	sess, err := p.transitionStore.Create(ctx, p.providerName, store)
	if err != nil {
		return idn.StepResult{}, err
	}

	authURL := p.oauth2Config.AuthCodeURL(
		state,
		oidc.Nonce(p.generateRandomState()),
		oauth2.S256ChallengeOption(verifier),
	)

	return idn.StepResult{
		TransitionId: sess.Id,
		Type:         idn.StepRedirect,
		RedirectURL:  authURL,
	}, nil
}

func (p *OIDCIdentityProvider) Continue(
	ctx context.Context,
	input idn.ContinueInput,
) (idn.StepResult, error) {
	req, err := p.parseContinuePayload(input.Payload)
	if err != nil {
		return idn.StepResult{}, err
	}

	sess, err := p.validateTransition(ctx, input.TransitionId, req.State)
	if err != nil {
		return idn.StepResult{}, err
	}

	if sess.Store.Flow != session.FlowKindOIDC || sess.Store.OIDC == nil {
		return idn.StepResult{}, errors.Join(
			idn.ErrInvalidSessionState,
			errors.New("expected oidc transition"),
		)
	}

	claims, err := p.exchangeAndVerify(
		ctx,
		req.Code,
		sess.Store.OIDC.PKCECodeVerifier,
	)
	if err != nil {
		return idn.StepResult{}, err
	}

	userID, err := p.accounts.ResolveOIDCLogin(
		ctx,
		p.providerName,
		claims.Subject,
		claims.Email,
		claims.EmailVerified,
		claims.Name,
		claims.Picture,
	)
	if err != nil {
		if errors.Is(err, idn.ErrOIDCManualAccountLinkingRequired) {
			return idn.StepResult{}, err
		}
		return idn.StepResult{}, errors.Join(
			idn.ErrAuthenticationFailed,
			err,
		)
	}

	authResult, err := p.accounts.IssueAuthenticatedSession(ctx, userID)
	if err != nil {
		return idn.StepResult{}, errors.Join(
			idn.ErrAuthenticationFailed,
			err,
		)
	}

	_ = p.transitionStore.Delete(ctx, sess.Id)

	return idn.StepResult{
		Type:                idn.StepComplete,
		AuthenticatedResult: authResult,
	}, nil
}

type continueRequest struct {
	Code  string
	State string
}

func (*OIDCIdentityProvider) parseContinuePayload(payload map[string]any) (continueRequest, error) {
	code, ok := payload[OIDCPayloadKeyCode].(string)
	if !ok || code == "" {
		return continueRequest{}, errors.Join(
			idn.ErrInvalidInput,
			errors.New("missing code"),
		)
	}

	state, ok := payload[OIDCPayloadKeyState].(string)
	if !ok || state == "" {
		return continueRequest{}, errors.Join(
			idn.ErrInvalidInput,
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
			idn.ErrSessionNotFound,
			err,
		)
	}

	if sess.Store.OIDC == nil || sess.Store.OIDC.OAuthState != state {
		return session.AuthSession{}, errors.Join(
			idn.ErrInvalidSessionState,
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
	rawIDToken, ok := token.Extra(OIDCTokenExtraIDToken).(string)
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
