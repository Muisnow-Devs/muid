package identity

import (
	"context"

	"github.com/google/uuid"
	claimspb "sanzi.io/muid/api/proto/shared/v1/claims"
	"sanzi.io/muid/pkg/clientmeta"
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
	// Client carries locale, timezone, and device context from pkg/clientmeta at session start.
	Client   clientmeta.ClientMeta
	Metadata map[string]any
}

// ContinueState selects which provider Continue path runs. Flow sets this explicitly;
// providers branch on it and validate fields for that state only.
type ContinueState string

const (
	ContinueStateUnspecified    ContinueState = ""
	ContinueStateChallenge      ContinueState = "challenge"
	ContinueStateResend         ContinueState = "resend"
	ContinueStateFinishRegister ContinueState = "finish_register"
)

type ContinueInput struct {
	TransitionId  string
	ContinueState ContinueState
	Payload       map[string]any
	// LinkSessionToken is the active session for linking flows (same as Start when required).
	LinkSessionToken string
	// FinishRegister is set only for ContinueStateFinishRegister (flow orchestration).
	FinishRegister *FinishRegisterInput
}

type FinishRegisterInput struct {
	RegisteredUserID uuid.UUID
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

// LoginCompletionContext holds supplementary data for post-login actions (e.g. outbound mail).
type LoginCompletionContext struct {
	Locale    string
	Timezone  string
	Device    string
	Location  string
	UserAgent string
	IPAddress string
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
	LoginCompletion  *LoginCompletionContext
	RegisterRequired *RegisterRequired
}

type IdentityProvider interface {
	Name() string
	Start(ctx context.Context, input StartInput) (StepResult, error)
	Continue(ctx context.Context, input ContinueInput) (StepResult, error)
}
