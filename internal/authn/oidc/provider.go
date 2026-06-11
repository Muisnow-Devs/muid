package oidc

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/google/uuid"

	profilepb "sanzi.io/muid/api/proto/profile/v1"
	"sanzi.io/muid/internal/authn/ent"
	"sanzi.io/muid/internal/authn/ent/oidcclient"
	"sanzi.io/muid/internal/authn/ent/oidcgrant"
	"sanzi.io/muid/internal/authn/ent/oidcscope"
	"sanzi.io/muid/internal/authn/oidc/policy"
	"sanzi.io/muid/internal/authn/oidc/store"
	"sanzi.io/muid/internal/oidctoken"
	"sanzi.io/muid/pkg/log"
)

// Standard OIDC scopes with provider-level semantics.
const (
	ScopeOpenID  = "openid"
	ScopeProfile = "profile"
	ScopeEmail   = "email"
)

// Prompt values supported on Authorize.
const (
	PromptNone    = "none"
	PromptConsent = "consent"
)

// Config is the static provider configuration.
type Config struct {
	Issuer                string
	AccessTokenTTL        time.Duration
	DeviceVerificationURI string
	DevicePollInterval    time.Duration
}

// Provider orchestrates the OIDC flows on top of the Ent and KV stores.
type Provider struct {
	db       *ent.Client
	codes    *store.KVCodeStore
	pendings *store.KVPendingStore
	devices  *store.KVDeviceStore
	eval     *policy.Evaluator
	signer   *oidctoken.Signer
	verifier *oidctoken.Verifier
	profile  profilepb.ProfileServiceClient
	cfg      Config
}

func NewProvider(
	db *ent.Client,
	codes *store.KVCodeStore,
	pendings *store.KVPendingStore,
	devices *store.KVDeviceStore,
	eval *policy.Evaluator,
	signer *oidctoken.Signer,
	verifier *oidctoken.Verifier,
	profile profilepb.ProfileServiceClient,
	cfg Config,
) *Provider {
	if cfg.AccessTokenTTL <= 0 {
		cfg.AccessTokenTTL = time.Hour
	}
	if cfg.DevicePollInterval <= 0 {
		cfg.DevicePollInterval = 5 * time.Second
	}
	return &Provider{
		db:       db,
		codes:    codes,
		pendings: pendings,
		devices:  devices,
		eval:     eval,
		signer:   signer,
		verifier: verifier,
		profile:  profile,
		cfg:      cfg,
	}
}

// Issuer returns the configured issuer URL.
func (p *Provider) Issuer() string {
	return p.cfg.Issuer
}

// DeviceVerificationURI returns the configured device verification page URL.
func (p *Provider) DeviceVerificationURI() string {
	return p.cfg.DeviceVerificationURI
}

// SupportedScopes lists every scope registered with the provider (for the
// discovery document).
func (p *Provider) SupportedScopes(ctx context.Context) ([]string, error) {
	return p.db.OIDCScope.Query().Order(oidcscope.ByID()).IDs(ctx)
}

// SessionUser is the authenticated first-party principal acting in a flow.
type SessionUser struct {
	UserID    uuid.UUID
	SessionID uuid.UUID
	// AuthTime is when the first-party session was established.
	AuthTime time.Time
}

// AuthorizeInput mirrors the OIDC authorization request parameters.
type AuthorizeInput struct {
	ClientID            string
	RedirectURI         string
	ResponseType        string
	Scopes              []string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	Prompt              string
}

// GrantedCode tells the gateway to redirect back with an authorization code.
type GrantedCode struct {
	Code        string
	State       string
	RedirectURI string
}

// ScopeDetail is the localized consent-screen description of one scope.
type ScopeDetail struct {
	Scope       string
	Name        string
	Description map[string]string
}

// ConsentRequirement asks the gateway to render the consent screen.
type ConsentRequirement struct {
	AuthorizationID    uuid.UUID
	ClientName         string
	VerificationStatus oidcclient.VerificationStatus
	Scopes             []ScopeDetail
}

// AuthorizeResult is exactly one of: granted, login required, or consent
// required.
type AuthorizeResult struct {
	Granted       *GrantedCode
	LoginRequired bool
	Consent       *ConsentRequirement
}

// Authorize validates an authorization request and either issues a code,
// requires login, or requires consent.
func (p *Provider) Authorize(
	ctx context.Context,
	in AuthorizeInput,
	user *SessionUser,
) (AuthorizeResult, error) {
	client, err := p.clientByClientID(ctx, in.ClientID)
	if err != nil {
		return AuthorizeResult{}, err
	}

	err = policy.ValidateAuthorizeRequest(
		client,
		callbackURIs(client),
		in.RedirectURI,
		in.ResponseType,
		in.CodeChallenge,
		in.CodeChallengeMethod,
	)
	if err != nil {
		return AuthorizeResult{}, authorizeRequestError(err)
	}

	err = policy.GrantTypeEnabled(client, policy.GrantTypeAuthorizationCode)
	if err != nil {
		return AuthorizeResult{}, oauthError(
			ErrCodeUnauthorizedClient,
			"authorization_code grant is not enabled for this client",
		)
	}
	err = policy.ClientUsable(client)
	if err != nil {
		return AuthorizeResult{}, oauthError(ErrCodeUnauthorizedClient, "client is disabled")
	}

	if user == nil {
		if in.Prompt == PromptNone {
			return AuthorizeResult{}, oauthError(ErrCodeLoginRequired, "")
		}
		return AuthorizeResult{LoginRequired: true}, nil
	}

	err = p.eval.AuthorizeUser(ctx, client, user.UserID, in.Scopes)
	if err != nil {
		return AuthorizeResult{}, accessPolicyError(err)
	}

	consented, err := p.hasConsent(ctx, user.UserID, client.ID, in.Scopes)
	if err != nil {
		return AuthorizeResult{}, err
	}
	if !consented || in.Prompt == PromptConsent {
		if in.Prompt == PromptNone {
			return AuthorizeResult{}, oauthError(ErrCodeConsentRequired, "")
		}
		return p.requireConsent(ctx, client, in, *user)
	}

	code, err := p.codes.Create(ctx, store.CodeRecord{
		ClientRefID:         client.ID,
		ClientID:            client.ClientID,
		UserID:              user.UserID,
		SessionID:           user.SessionID,
		RedirectURI:         in.RedirectURI,
		Scopes:              in.Scopes,
		Nonce:               in.Nonce,
		CodeChallenge:       in.CodeChallenge,
		CodeChallengeMethod: in.CodeChallengeMethod,
		AuthTime:            user.AuthTime.Unix(),
	})
	if err != nil {
		return AuthorizeResult{}, err
	}

	p.touchGrant(ctx, user.UserID, client.ID)
	return AuthorizeResult{Granted: &GrantedCode{
		Code:        code,
		State:       in.State,
		RedirectURI: in.RedirectURI,
	}}, nil
}

func (p *Provider) requireConsent(
	ctx context.Context,
	client *ent.OIDCClient,
	in AuthorizeInput,
	user SessionUser,
) (AuthorizeResult, error) {
	id, err := p.pendings.Create(ctx, store.PendingAuthorization{
		ClientRefID:         client.ID,
		ClientID:            client.ClientID,
		UserID:              user.UserID,
		SessionID:           user.SessionID,
		RedirectURI:         in.RedirectURI,
		Scopes:              in.Scopes,
		State:               in.State,
		Nonce:               in.Nonce,
		CodeChallenge:       in.CodeChallenge,
		CodeChallengeMethod: in.CodeChallengeMethod,
		AuthTime:            user.AuthTime.Unix(),
	})
	if err != nil {
		return AuthorizeResult{}, err
	}

	return AuthorizeResult{Consent: &ConsentRequirement{
		AuthorizationID:    id,
		ClientName:         client.ClientName,
		VerificationStatus: client.VerificationStatus,
		Scopes:             p.scopeDetails(ctx, in.Scopes),
	}}, nil
}

// ConsentDenial tells the gateway to redirect back with an OAuth error.
type ConsentDenial struct {
	Err         *OAuthError
	RedirectURI string
	State       string
}

// ConsentOutcome is exactly one of granted or denied.
type ConsentOutcome struct {
	Granted *GrantedCode
	Denied  *ConsentDenial
}

// DecideConsent applies the user's consent-screen decision.
func (p *Provider) DecideConsent(
	ctx context.Context,
	user SessionUser,
	authorizationID uuid.UUID,
	approve bool,
) (ConsentOutcome, error) {
	pending, err := p.pendings.Consume(ctx, authorizationID)
	if errors.Is(err, store.ErrNotFound) {
		return ConsentOutcome{}, ErrPendingNotFound
	}
	if err != nil {
		return ConsentOutcome{}, err
	}
	if pending.UserID != user.UserID {
		return ConsentOutcome{}, ErrWrongUser
	}

	denial := func(oauthErr *OAuthError) ConsentOutcome {
		return ConsentOutcome{Denied: &ConsentDenial{
			Err:         oauthErr,
			RedirectURI: pending.RedirectURI,
			State:       pending.State,
		}}
	}

	if !approve {
		return denial(oauthError(ErrCodeAccessDenied, "user denied the request")), nil
	}

	// Re-check: the client or the user's access may have changed while the
	// consent screen was open.
	client, err := p.clientByRefID(ctx, pending.ClientRefID)
	if err != nil {
		if errors.Is(err, ErrClientNotFound) {
			return denial(oauthError(ErrCodeUnauthorizedClient, "client no longer available")), nil
		}
		return ConsentOutcome{}, err
	}
	err = p.eval.AuthorizeUser(ctx, client, user.UserID, pending.Scopes)
	if err != nil {
		oauthErr, ok := AsOAuthError(accessPolicyError(err))
		if !ok {
			return ConsentOutcome{}, err
		}
		return denial(oauthErr), nil
	}

	err = p.upsertGrant(ctx, user.UserID, client.ID, pending.Scopes)
	if err != nil {
		return ConsentOutcome{}, err
	}

	code, err := p.codes.Create(ctx, store.CodeRecord{
		ClientRefID:         pending.ClientRefID,
		ClientID:            pending.ClientID,
		UserID:              pending.UserID,
		SessionID:           pending.SessionID,
		RedirectURI:         pending.RedirectURI,
		Scopes:              pending.Scopes,
		Nonce:               pending.Nonce,
		CodeChallenge:       pending.CodeChallenge,
		CodeChallengeMethod: pending.CodeChallengeMethod,
		AuthTime:            pending.AuthTime,
	})
	if err != nil {
		return ConsentOutcome{}, err
	}

	return ConsentOutcome{Granted: &GrantedCode{
		Code:        code,
		State:       pending.State,
		RedirectURI: pending.RedirectURI,
	}}, nil
}

// clientByClientID loads an active client (with callback URIs) by its public
// client_id.
func (p *Provider) clientByClientID(ctx context.Context, clientID string) (*ent.OIDCClient, error) {
	client, err := p.db.OIDCClient.Query().
		Where(oidcclient.ClientID(clientID), oidcclient.DeletedAtIsNil()).
		WithCallbackUrls().
		Only(ctx)
	if ent.IsNotFound(err) {
		return nil, ErrClientNotFound
	}
	if err != nil {
		return nil, err
	}
	return client, nil
}

func (p *Provider) clientByRefID(ctx context.Context, id uuid.UUID) (*ent.OIDCClient, error) {
	client, err := p.db.OIDCClient.Query().
		Where(oidcclient.ID(id), oidcclient.DeletedAtIsNil()).
		Only(ctx)
	if ent.IsNotFound(err) {
		return nil, ErrClientNotFound
	}
	if err != nil {
		return nil, err
	}
	return client, nil
}

func callbackURIs(client *ent.OIDCClient) []string {
	uris := make([]string, 0, len(client.Edges.CallbackUrls))
	for _, callback := range client.Edges.CallbackUrls {
		uris = append(uris, callback.URI)
	}
	return uris
}

// hasConsent reports whether an unrevoked grant already covers all requested
// scopes.
func (p *Provider) hasConsent(
	ctx context.Context,
	userID, clientRefID uuid.UUID,
	requestedScopes []string,
) (bool, error) {
	grant, err := p.db.OIDCGrant.Query().
		Where(
			oidcgrant.UserID(userID),
			oidcgrant.ClientRefID(clientRefID),
			oidcgrant.RevokedAtIsNil(),
		).
		Only(ctx)
	if ent.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return policy.ScopesAllowed(grant.Scopes, requestedScopes) == nil, nil
}

// upsertGrant records (or refreshes) the user's consent for the client,
// merging newly approved scopes into any existing grant.
func (p *Provider) upsertGrant(
	ctx context.Context,
	userID, clientRefID uuid.UUID,
	scopes []string,
) error {
	now := time.Now()
	grant, err := p.db.OIDCGrant.Query().
		Where(oidcgrant.UserID(userID), oidcgrant.ClientRefID(clientRefID)).
		Only(ctx)
	if ent.IsNotFound(err) {
		return p.db.OIDCGrant.Create().
			SetUserID(userID).
			SetClientRefID(clientRefID).
			SetScopes(scopes).
			SetLastUsedAt(now).
			Exec(ctx)
	}
	if err != nil {
		return err
	}

	merged := grant.Scopes
	if !grant.RevokedAt.IsZero() {
		// A revoked grant's old scopes are stale; start over from the newly
		// approved set.
		merged = nil
	}
	for _, scope := range scopes {
		if !slices.Contains(merged, scope) {
			merged = append(merged, scope)
		}
	}

	return p.db.OIDCGrant.UpdateOneID(grant.ID).
		SetScopes(merged).
		ClearRevokedAt().
		SetLastUsedAt(now).
		Exec(ctx)
}

// touchGrant best-effort bumps last_used_at on the consent grant.
func (p *Provider) touchGrant(ctx context.Context, userID, clientRefID uuid.UUID) {
	err := p.db.OIDCGrant.Update().
		Where(
			oidcgrant.UserID(userID),
			oidcgrant.ClientRefID(clientRefID),
			oidcgrant.RevokedAtIsNil(),
		).
		SetLastUsedAt(time.Now()).
		Exec(ctx)
	if err != nil {
		log.LogUnexpected(ctx, "oidc grant last_used_at", err.Error(), log.UserID(userID))
	}
}

// scopeDetails resolves consent-screen metadata for the requested scopes,
// falling back to the bare scope string when unregistered.
func (p *Provider) scopeDetails(ctx context.Context, scopes []string) []ScopeDetail {
	details := make([]ScopeDetail, 0, len(scopes))
	rows, err := p.db.OIDCScope.Query().Where(oidcscope.IDIn(scopes...)).All(ctx)
	if err != nil {
		log.LogUnexpected(ctx, "oidc scope details", err.Error())
		rows = nil
	}

	byID := make(map[string]*ent.OIDCScope, len(rows))
	for _, row := range rows {
		byID[row.ID] = row
	}
	for _, scope := range scopes {
		detail := ScopeDetail{Scope: scope, Name: scope}
		if row := byID[scope]; row != nil {
			detail.Name = row.Name
			detail.Description = row.Description
		}
		details = append(details, detail)
	}
	return details
}

// authorizeRequestError maps request-shape validation failures to their
// protocol form.
func authorizeRequestError(err error) error {
	switch {
	case errors.Is(err, policy.ErrRedirectURINotRegistered):
		return ErrRedirectURINotRegistered
	case errors.Is(err, policy.ErrUnsupportedResponseType):
		return oauthError(ErrCodeUnsupportedResponseType, "only response_type=code is supported")
	case errors.Is(err, policy.ErrPKCERequired):
		return oauthError(ErrCodeInvalidRequest, "code_challenge is required for public clients")
	case errors.Is(err, policy.ErrPKCEMethodUnsupported):
		return oauthError(ErrCodeInvalidRequest, "only code_challenge_method=S256 is supported")
	default:
		return err
	}
}

// accessPolicyError maps policy decisions to their protocol form.
func accessPolicyError(err error) error {
	switch {
	case errors.Is(err, policy.ErrClientDisabled):
		return oauthError(ErrCodeUnauthorizedClient, "client is disabled")
	case errors.Is(err, policy.ErrAccessDenied):
		return oauthError(ErrCodeAccessDenied, "you do not have access to this application")
	case errors.Is(err, policy.ErrScopeNotAllowed):
		return oauthError(ErrCodeInvalidScope, "requested scope is not allowed for this client")
	default:
		return err
	}
}
