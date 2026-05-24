package session

import (
	"context"
	"encoding/json"

	"github.com/go-webauthn/webauthn/webauthn"
)

type ProviderData struct {
	Type string          `json:"type"`
	Raw  json.RawMessage `json:"raw"`
}

type AuthSession struct {
	Id       string
	Provider string

	Store SessionStore

	CreatedAt int64
	UpdatedAt int64
	ExpiresAt int64
}

// AuthFlowKind discriminates which flow payload is active in [FlowState].
// Only one of Email, OIDC, or Passkey should be non-nil for a given session.
type AuthFlowKind string

const (
	FlowKindUnspecified AuthFlowKind = ""
	FlowKindEmailOTP    AuthFlowKind = "email_otp"
	FlowKindOIDC        AuthFlowKind = "oidc"
	FlowKindPasskey     AuthFlowKind = "passkey"
)

// EmailOTPFlow holds email OTP transition state.
type EmailOTPFlow struct {
	Email string `json:"email"`
	// Intent is login or change_email when linking.
	Intent string `json:"intent,omitempty"`
	// SubjectUserID is the authenticated user performing a change_email flow.
	SubjectUserID string `json:"subject_user_id,omitempty"`
	OldEmail      string `json:"old_email,omitempty"`
}

// OIDCFlow holds OIDC/PKCE transition state.
type OIDCFlow struct {
	OAuthState       string `json:"oauth_state"`
	PKCECodeVerifier string `json:"pkce_code_verifier"`
}

// PasskeyFlow holds WebAuthn ceremony state for the passkey transition.
type PasskeyFlow struct {
	// Ceremony is authentication (assertion) or registration (attestation).
	Ceremony string               `json:"ceremony,omitempty"`
	Session  webauthn.SessionData `json:"session"`
	// SubjectUserID is set for register/link flows.
	SubjectUserID string `json:"subject_user_id,omitempty"`
}

// RegisterPendingClaims mirrors shared IdentityInformation fields stored on the transition.
type RegisterPendingClaims struct {
	Email             string `json:"email"`
	EmailVerified     bool   `json:"email_verified,omitempty"`
	FederatedProvider string `json:"federated_provider,omitempty"`
	FederatedSubject  string `json:"federated_subject,omitempty"`
	Name              string `json:"name,omitempty"`
	Picture           string `json:"picture,omitempty"`
}

// RegisterPending holds signup claims and, after login-flow provision, the new user id.
type RegisterPending struct {
	Claims            RegisterPendingClaims `json:"claims"`
	ProvisionedUserID string                `json:"provisioned_user_id,omitempty"`
}

type SessionStore struct {
	Attempts int      `json:"attempts"`
	Step     AuthStep `json:"step"`

	Flow FlowState `json:"flow"`

	// Locale and Timezone come from StartAuthSession for mail formatting.
	Locale   string `json:"locale,omitempty"`
	Timezone string `json:"timezone,omitempty"`

	// PendingRegister is set when a provider needs login-flow provision before finish linking.
	PendingRegister *RegisterPending `json:"pending_register,omitempty"`
}

type AuthTransitionStore interface {
	Create(ctx context.Context, provider string, store SessionStore) (AuthSession, error)
	Get(ctx context.Context, id string) (AuthSession, error)
	Update(ctx context.Context, id string, store SessionStore) error
	Delete(ctx context.Context, id string) error
}
