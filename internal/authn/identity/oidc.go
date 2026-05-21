package identity

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
	"sanzi.io/muid/internal/authn/account"
	idn "sanzi.io/muid/internal/identity"
	"sanzi.io/muid/internal/session"
	"sanzi.io/muid/pkg/utils"
)

const (
	OIDCPayloadKeyCode    = "code"
	OIDCPayloadKeyState   = "state"
	OIDCTokenExtraIDToken = "id_token"
	OIDCScopeProfile      = "profile"
	OIDCScopeEmail        = "email"
)

type OIDCIdentityProvider struct {
	transitionStore session.AuthTransitionStore
	accounts        *account.Accounts

	providerName string
	provider     *oidc.Provider
	oauth2Config *oauth2.Config
	verifier     *oidc.IDTokenVerifier
	claimFields  OIDCClaimFields
}

type OIDCClaims struct {
	Subject string
	Name    string
	Picture string

	Email         string
	EmailVerified bool
}

type OIDCProviderConfig struct {
	Name         string
	Endpoint     string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	ClaimFields  OIDCClaimFields
}

type OIDCClaimFields struct {
	Subject       string
	Name          string
	Picture       string
	Email         string
	EmailVerified string
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
	accounts *account.Accounts,
) (idn.IdentityProvider, error) {
	provider, err := oidc.NewProvider(ctx, config.Endpoint)
	if err != nil {
		return nil, err
	}

	oauth2Config := &oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  config.RedirectURL,
		Scopes:       oidcScopes(config.Scopes),
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: config.ClientID})

	return &OIDCIdentityProvider{
		providerName:    config.Name,
		provider:        provider,
		oauth2Config:    oauth2Config,
		verifier:        verifier,
		claimFields:     oidcClaimFieldsWithDefaults(config.ClaimFields),
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

	store := session.OIDCStore(session.StepStart, &session.OIDCFlow{
		OAuthState:       state,
		PKCECodeVerifier: verifier,
	})

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
	if idn.FinishRegisterRequested(input.Payload) {
		return p.continueFinishOIDCRegister(ctx, input)
	}

	req, err := p.parseContinuePayload(input.Payload)
	if err != nil {
		return idn.StepResult{}, err
	}

	sess, err := p.validateTransition(ctx, input.TransitionId, req.State)
	if err != nil {
		return idn.StepResult{}, err
	}

	oidcFlow, ok := sess.Store.OIDCFlowState()
	if !ok {
		return idn.StepResult{}, idn.ErrInvalidSessionState
	}

	claims, err := p.exchangeAndVerify(
		ctx,
		req.Code,
		oidcFlow.PKCECodeVerifier,
	)
	if err != nil {
		return idn.StepResult{}, err
	}

	userID, reg, err := p.accounts.OIDC.LookupOIDCLogin(
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

	if reg != nil {
		store := sess.Store.WithRegisterPending(
			session.RegisterPendingClaimsFromProto(reg.Identity),
		)
		err = p.transitionStore.Update(ctx, sess.Id, store)
		if err != nil {
			return idn.StepResult{}, err
		}

		return idn.StepResult{
			TransitionId:     sess.Id,
			Type:             idn.StepRegisterRequired,
			RegisterRequired: reg,
		}, nil
	}

	p.transitionStore.Delete(ctx, sess.Id)

	return idn.StepResult{
		Type: idn.StepAuthenticated,
		Authenticated: &idn.AuthenticatedIdentity{
			UserID: userID.String(),
		},
	}, nil
}

func (p *OIDCIdentityProvider) continueFinishOIDCRegister(
	ctx context.Context,
	input idn.ContinueInput,
) (idn.StepResult, error) {
	sess, err := p.transitionStore.Get(ctx, input.TransitionId)
	if err != nil {
		return idn.StepResult{}, errors.Join(idn.ErrSessionNotFound, err)
	}

	pending, ok := sess.Store.PendingRegisterState()
	if !ok || pending.ProvisionedUserID == "" {
		return idn.StepResult{}, idn.ErrInvalidSessionState
	}

	provisioned, err := uuid.Parse(strings.TrimSpace(pending.ProvisionedUserID))
	if err != nil {
		return idn.StepResult{}, errors.Join(idn.ErrInvalidSessionState, err)
	}

	claims := pending.Claims
	provider := strings.TrimSpace(claims.FederatedProvider)
	subject := strings.TrimSpace(claims.FederatedSubject)
	if provider == "" || subject == "" {
		return idn.StepResult{}, idn.ErrInvalidSessionState
	}

	linked, err := ensureFederatedLink(
		ctx,
		p.accounts.Store.DB,
		provider,
		subject,
		provisioned,
		claims,
	)
	if err != nil {
		return idn.StepResult{}, err
	}

	return finishRegisterAfterLink(ctx, p.transitionStore, sess.Id, linked, provisioned)
}

type continueRequest struct {
	Code  string
	State string
}

func (*OIDCIdentityProvider) parseContinuePayload(payload map[string]any) (continueRequest, error) {
	code, ok := payload[OIDCPayloadKeyCode].(string)
	if !ok || code == "" {
		return continueRequest{}, idn.ErrInvalidInput
	}

	state, ok := payload[OIDCPayloadKeyState].(string)
	if !ok || state == "" {
		return continueRequest{}, idn.ErrInvalidInput
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

	oidcFlow, ok := sess.Store.OIDCFlowState()
	if !ok || oidcFlow.OAuthState != state {
		return session.AuthSession{}, idn.ErrInvalidSessionState
	}

	return sess, nil
}

func (p *OIDCIdentityProvider) exchangeAndVerify(
	ctx context.Context,
	code string,
	verifier string,
) (OIDCClaims, error) {
	token, err := p.oauth2Config.Exchange(
		ctx,
		code,
		oauth2.VerifierOption(verifier),
	)
	if err != nil {
		return OIDCClaims{}, err
	}

	idToken, err := p.extractIDToken(token)
	if err != nil {
		return OIDCClaims{}, err
	}

	claims, err := p.verifyIDToken(ctx, idToken)
	if err != nil {
		return OIDCClaims{}, err
	}

	claims, err = p.mergeUserInfoClaims(ctx, token, claims)
	if err != nil {
		return OIDCClaims{}, err
	}

	return claims, nil
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

	var raw map[string]json.RawMessage
	err = idToken.Claims(&raw)
	if err != nil {
		return OIDCClaims{}, err
	}

	return oidcClaimsFromRaw(raw, p.claimFields), nil
}

func (p *OIDCIdentityProvider) mergeUserInfoClaims(
	ctx context.Context,
	token *oauth2.Token,
	claims OIDCClaims,
) (OIDCClaims, error) {
	if !oidcClaimsNeedUserInfo(claims, p.claimFields) {
		return claims, nil
	}

	userInfo, err := p.provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
	if err != nil {
		return claims, nil
	}

	var raw map[string]json.RawMessage
	err = userInfo.Claims(&raw)
	if err != nil {
		return OIDCClaims{}, err
	}

	userInfoClaims := oidcClaimsFromRaw(raw, p.claimFields)
	return oidcMergeClaims(claims, userInfoClaims), nil
}

func oidcScopes(scopes []string) []string {
	if len(scopes) == 0 {
		return []string{oidc.ScopeOpenID, OIDCScopeProfile, OIDCScopeEmail}
	}

	out := utils.TrimNonEmpty(scopes)
	hasOpenID := false
	for _, scope := range out {
		if scope == oidc.ScopeOpenID {
			hasOpenID = true
		}
	}
	if !hasOpenID {
		out = append([]string{oidc.ScopeOpenID}, out...)
	}
	return out
}

func oidcClaimFieldsWithDefaults(fields OIDCClaimFields) OIDCClaimFields {
	utils.DefaultIfEmpty(&fields.Subject, "sub")
	utils.DefaultIfEmpty(&fields.Name, "name")
	utils.DefaultIfEmpty(&fields.Picture, "picture")
	utils.DefaultIfEmpty(&fields.Email, "email")
	utils.DefaultIfEmpty(&fields.EmailVerified, "email_verified")

	return fields
}

func oidcClaimsFromRaw(raw map[string]json.RawMessage, fields OIDCClaimFields) OIDCClaims {
	fields = oidcClaimFieldsWithDefaults(fields)
	return OIDCClaims{
		Subject:       utils.JSONStringField(raw, fields.Subject),
		Name:          utils.JSONStringField(raw, fields.Name),
		Picture:       utils.JSONStringField(raw, fields.Picture),
		Email:         utils.JSONStringField(raw, fields.Email),
		EmailVerified: utils.JSONBoolField(raw, fields.EmailVerified),
	}
}

func oidcClaimsNeedUserInfo(claims OIDCClaims, fields OIDCClaimFields) bool {
	fields = oidcClaimFieldsWithDefaults(fields)
	return fields.Name != "" && claims.Name == "" ||
		fields.Picture != "" && claims.Picture == "" ||
		fields.Email != "" && claims.Email == ""
}

func oidcMergeClaims(primary, secondary OIDCClaims) OIDCClaims {
	utils.DefaultIfEmpty(&primary.Subject, secondary.Subject)
	utils.DefaultIfEmpty(&primary.Name, secondary.Name)
	utils.DefaultIfEmpty(&primary.Picture, secondary.Picture)
	utils.DefaultIfEmpty(&primary.Email, secondary.Email)

	utils.DefaultIfFalse(&primary.EmailVerified, secondary.EmailVerified)

	return primary
}
