package identity

import (
	"context"

	claimspb "sanzi.io/muid/api/proto/shared/v1/claims"
)

type StepType string

const (
	StepRedirect  StepType = "redirect"
	StepInput     StepType = "input"
	StepChallenge StepType = "challenge"

	// Terminal auth outcomes (session issuance and registration belong in login flows).
	StepAuthenticated    StepType = "authenticated"
	StepRegisterRequired StepType = "register_required"
	StepLinked           StepType = "linked"
)

// AuthIntent mirrors muid.authn.v1.basic.AuthIntent for provider flows.
type AuthIntent string

const (
	IntentUnspecified    AuthIntent = ""
	IntentLogin          AuthIntent = "login"
	IntentLinkAccount    AuthIntent = "link_account"
	IntentReauthenticate AuthIntent = "reauthenticate"
)

type StartInput struct {
	Provider   string
	Identifier string
	Intent     AuthIntent
	// LinkSessionToken is the wire session token (selector.validator) required for linking flows.
	LinkSessionToken string
	// Locale is the client BCP-47 locale for outbound mail; empty defaults to "en".
	Locale string
	// Timezone is an IANA time zone for outbound mail; empty means UTC.
	Timezone string
	Metadata map[string]any
}

// ContinuePayloadFinishRegister is set by login-flow orchestration after ProvisionUser (not from wire clients).
const ContinuePayloadFinishRegister = "__finish_register"

type ContinueInput struct {
	TransitionId string
	Payload      map[string]any
	// LinkSessionToken is the active session for linking flows (same as Start when required).
	LinkSessionToken string
}

// FinishRegisterRequested reports whether Continue should complete post-provision linking.
func FinishRegisterRequested(payload map[string]any) bool {
	if payload == nil {
		return false
	}
	v, ok := payload[ContinuePayloadFinishRegister].(bool)
	return ok && v
}

// StepPayload holds provider-specific challenge or ceremony material.
type StepPayload struct {
	Passkey *PasskeyChallengePayload
}

type PasskeyChallengePayload struct {
	Ceremony                               string
	PublicKeyCredentialRequestOptionsJSON  string
	PublicKeyCredentialCreationOptionsJSON string
	TimeoutMillis                          int64
}

// AuthenticatedIdentity is the provider auth outcome before session issuance.
type AuthenticatedIdentity struct {
	UserID string
}

// RegisterRequired carries identity claims for the login flow to provision an account.
type RegisterRequired struct {
	Identity *claimspb.IdentityInformation
}

type StepResult struct {
	TransitionId string
	Type         StepType

	RedirectURL    string
	RequiredFields []string
	Payload        *StepPayload

	Authenticated    *AuthenticatedIdentity
	RegisterRequired *RegisterRequired
}

type IdentityProvider interface {
	Name() string
	Start(ctx context.Context, input StartInput) (StepResult, error)
	Continue(ctx context.Context, input ContinueInput) (StepResult, error)
}
