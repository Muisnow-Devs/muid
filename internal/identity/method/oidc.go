package method

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"sanzi.io/muid/api/proto/shared/v1/claims"
	"sanzi.io/muid/internal/authn/config"
	identitystore "sanzi.io/muid/internal/identity/store"
	"sanzi.io/muid/internal/session"
	"sanzi.io/muid/pkg/shared/authn"
	"sanzi.io/muid/pkg/utils"
)

// OIDCCallbackPayload carries the authorization code and state from the redirect callback.
type OIDCCallbackPayload struct {
	Code  string
	State string
}

func (OIDCCallbackPayload) PayloadKind() string {
	return "oidc_callback"
}

// OIDCMethod drives an OIDC authentication flow.
type OIDCMethod struct {
	providerName    string
	provider        *oidc.Provider
	oauth2Config    *oauth2.Config
	verifier        *oidc.IDTokenVerifier
	claimFields     config.OIDCClaimFields
	identityStore   identitystore.IdentityStore
	transitionStore session.AuthTransitionStore
}

func NewOIDCMethod(
	ctx context.Context,
	cfg config.OIDCProviderConfig,
	identityStore identitystore.IdentityStore,
	transitionStore session.AuthTransitionStore,
) (IdentityMethod, error) {
	provider, err := oidc.NewProvider(ctx, cfg.Endpoint)
	if err != nil {
		return nil, err
	}

	oauth2Config := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  cfg.RedirectURL,
		Scopes:       oidcScopes(cfg.Scopes),
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: cfg.ClientID})

	return &OIDCMethod{
		providerName:    cfg.Name,
		provider:        provider,
		oauth2Config:    oauth2Config,
		verifier:        verifier,
		claimFields:     oidcClaimFieldsWithDefaults(cfg.ClaimFields),
		identityStore:   identityStore,
		transitionStore: transitionStore,
	}, nil
}

func (m *OIDCMethod) Name() string {
	return m.providerName
}

func (m *OIDCMethod) Start(
	ctx context.Context,
	sessionStore session.SessionStore,
	req StartRequest,
) (Step, error) {
	state, err := generateRandomState()
	if err != nil {
		return nil, err
	}
	nonce, err := generateRandomState()
	if err != nil {
		return nil, err
	}
	verifier := oauth2.GenerateVerifier()

	sessionStore.Flow = &session.OIDCFlow{
		OAuthState:       state,
		PKCECodeVerifier: verifier,
	}

	sess, err := m.transitionStore.Create(ctx, m.Name(), sessionStore)
	if err != nil {
		return nil, err
	}

	authURL := m.oauth2Config.AuthCodeURL(
		state,
		oidc.Nonce(nonce),
		oauth2.S256ChallengeOption(verifier),
	)

	return RedirectStep{
		TransitionID: sess.ID,
		RedirectURL:  authURL,
	}, nil
}

func (m *OIDCMethod) Continue(
	ctx context.Context,
	req ContinueRequest,
) (Step, error) {
	tid := req.TransitionID
	sess, err := m.transitionStore.Get(ctx, tid)
	if err != nil {
		if errors.Is(err, session.ErrSessionNotFound) {
			return &FailureStep{
				Code:    authn.ErrCodeTransitionNotFound,
				Message: "transition not found",
			}, nil
		}
		if errors.Is(err, session.ErrSessionExpired) {
			return &FailureStep{
				Code:    authn.ErrCodeTransitionExpired,
				Message: "transition expired",
			}, nil
		}
		return nil, err
	}

	oidcFlow, ok := sess.Store.Flow.(*session.OIDCFlow)
	if !ok {
		return &FailureStep{
			Code:    authn.ErrCodeInvalidSessionState,
			Message: "invalid oidc flow state",
		}, nil
	}

	callback, ok := req.Payload.(OIDCCallbackPayload)
	if !ok {
		return &FailureStep{
			Code:    authn.ErrCodeInvalidInput,
			Message: "expected OIDCCallbackPayload",
		}, nil
	}

	if oidcFlow.OAuthState != callback.State {
		return &FailureStep{
			Code:    authn.ErrCodeInvalidSessionState,
			Message: "OIDC oauth state mismatch",
		}, nil
	}

	token, err := m.oauth2Config.Exchange(
		ctx,
		callback.Code,
		oauth2.VerifierOption(oidcFlow.PKCECodeVerifier),
	)
	if err != nil {
		return &FailureStep{
			Code:    authn.ErrCodeAuthenticationFailed,
			Message: "token exchange failed: " + err.Error(),
		}, nil
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return &FailureStep{
			Code:    authn.ErrCodeAuthenticationFailed,
			Message: "missing id_token in token response",
		}, nil
	}

	idToken, err := m.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return &FailureStep{
			Code:    authn.ErrCodeAuthenticationFailed,
			Message: "id_token verification failed: " + err.Error(),
		}, nil
	}

	var raw map[string]json.RawMessage
	err = idToken.Claims(&raw)
	if err != nil {
		return nil, err
	}

	oidcClaims := oidcUserClaimsFromRaw(raw, m.claimFields)

	// Fetch UserInfo if fields are missing
	if oidcUserClaimsNeedUserInfo(oidcClaims, m.claimFields) {
		userInfo, err := m.provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
		if err == nil {
			var uiRaw map[string]json.RawMessage
			if err := userInfo.Claims(&uiRaw); err == nil {
				uiClaims := oidcUserClaimsFromRaw(uiRaw, m.claimFields)
				oidcClaims = oidcMergeClaims(oidcClaims, uiClaims)
			}
		}
	}

	if oidcClaims.Subject == "" {
		return &FailureStep{
			Code:    authn.ErrCodeAuthenticationFailed,
			Message: "missing subject in OIDC claims",
		}, nil
	}

	claimsInfo := &claims.IdentityInformation{}
	claimsInfo.SetEmail(oidcClaims.Email)
	claimsInfo.SetEmailVerified(oidcClaims.EmailVerified)
	claimsInfo.SetFederatedProvider(m.Name())
	claimsInfo.SetFederatedSubject(oidcClaims.Subject)
	if oidcClaims.Name != "" {
		claimsInfo.SetName(oidcClaims.Name)
	}
	if oidcClaims.Picture != "" {
		claimsInfo.SetPicture(oidcClaims.Picture)
	}

	return &VerifiedStep{
		Provider: m.Name(),
		Subject:  oidcClaims.Subject,
		Identity: VerifiedIdentity{
			UserClaims: claimsInfo,
			IdentityClaims: identitystore.OIDCIdentityClaims{
				Provider:      m.Name(),
				Subject:       oidcClaims.Subject,
				DisplayName:   claimsInfo.GetName(),
				AvatarURL:     claimsInfo.GetPicture(),
				Email:         claimsInfo.GetEmail(),
				EmailVerified: claimsInfo.GetEmailVerified(),
			},
		},
	}, nil
}

// OIDCUserClaims is the subset of OIDC claims used by the method.
type OIDCUserClaims struct {
	Subject       string
	Name          string
	Picture       string
	Email         string
	EmailVerified bool
}

func generateRandomState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func oidcScopes(scopes []string) []string {
	if len(scopes) == 0 {
		return []string{oidc.ScopeOpenID, "profile", "email"}
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

func oidcClaimFieldsWithDefaults(fields config.OIDCClaimFields) config.OIDCClaimFields {
	utils.DefaultIfEmpty(&fields.Subject, "sub")
	utils.DefaultIfEmpty(&fields.Name, "name")
	utils.DefaultIfEmpty(&fields.Picture, "picture")
	utils.DefaultIfEmpty(&fields.Email, "email")
	utils.DefaultIfEmpty(&fields.EmailVerified, "email_verified")
	return fields
}

func oidcUserClaimsFromRaw(
	raw map[string]json.RawMessage,
	fields config.OIDCClaimFields,
) OIDCUserClaims {
	fields = oidcClaimFieldsWithDefaults(fields)
	return OIDCUserClaims{
		Subject:       utils.JSONStringField(raw, fields.Subject),
		Name:          utils.JSONStringField(raw, fields.Name),
		Picture:       utils.JSONStringField(raw, fields.Picture),
		Email:         utils.JSONStringField(raw, fields.Email),
		EmailVerified: utils.JSONBoolField(raw, fields.EmailVerified),
	}
}

func oidcUserClaimsNeedUserInfo(claims OIDCUserClaims, fields config.OIDCClaimFields) bool {
	fields = oidcClaimFieldsWithDefaults(fields)
	return (fields.Name != "" && claims.Name == "") ||
		(fields.Picture != "" && claims.Picture == "") ||
		(fields.Email != "" && claims.Email == "")
}

func oidcMergeClaims(primary, secondary OIDCUserClaims) OIDCUserClaims {
	utils.DefaultIfEmpty(&primary.Subject, secondary.Subject)
	utils.DefaultIfEmpty(&primary.Name, secondary.Name)
	utils.DefaultIfEmpty(&primary.Picture, secondary.Picture)
	utils.DefaultIfEmpty(&primary.Email, secondary.Email)
	utils.DefaultIfFalse(&primary.EmailVerified, secondary.EmailVerified)
	return primary
}
