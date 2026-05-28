package session

import (
	"context"
	"encoding/json"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
)

type ProviderData struct {
	Type string          `json:"type"`
	Raw  json.RawMessage `json:"raw"`
}

type AuthIntent string

const (
	AuthIntentLogin       AuthIntent = "login"
	AuthIntentLinkAccount AuthIntent = "link_account"
	AuthIntentReauth      AuthIntent = "reauthenticate"
)

type AuthSession struct {
	Id       uuid.UUID
	Provider string
	Intent   AuthIntent

	Store SessionStore

	CreatedAt int64
	UpdatedAt int64
	ExpiresAt int64
}

// SessionPayload represents flow-specific payload transition state.
type SessionPayload interface {
	PayloadKind() string
}

// EmailOTPFlow holds email OTP transition state.
type EmailOTPFlow struct {
	Email string `json:"email"`
}

func (EmailOTPFlow) PayloadKind() string { return "email_otp" }

// OIDCFlow holds OIDC/PKCE ceremony state only.
type OIDCFlow struct {
	OAuthState       string `json:"oauth_state"`
	PKCECodeVerifier string `json:"pkce_code_verifier"`
}

func (OIDCFlow) PayloadKind() string { return "oidc" }

// PasskeyFlow holds WebAuthn ceremony state for the passkey transition.
type PasskeyFlow struct {
	// Ceremony is authentication (assertion) or registration (attestation).
	Ceremony string               `json:"ceremony,omitempty"`
	Session  webauthn.SessionData `json:"session"`
	// SubjectUserID is set for register/link flows.
	SubjectUserID string `json:"subject_user_id,omitempty"`
}

func (PasskeyFlow) PayloadKind() string { return "passkey" }

// RegisterPendingClaims mirrors shared IdentityInformation fields stored on the transition.
type RegisterPendingClaims struct {
	Email             string `json:"email"`
	EmailVerified     bool   `json:"email_verified,omitempty"`
	FederatedProvider string `json:"federated_provider,omitempty"`
	FederatedSubject  string `json:"federated_subject,omitempty"`
	Name              string `json:"name,omitempty"`
	Picture           string `json:"picture,omitempty"`
}

type SessionMetadata struct {
	Locale    string `json:"locale,omitempty"`
	Timezone  string `json:"timezone,omitempty"`
	Device    string `json:"device,omitempty"`
	Location  string `json:"location,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
	IPAddress string `json:"ip_address,omitempty"`
}

type SessionStore struct {
	Attempts int      `json:"attempts"`
	Step     AuthStep `json:"step"`

	Flow   SessionPayload `json:"-"`
	Intent AuthIntent     `json:"intent"`

	// LinkUserID is the authenticated user for link_account / reauthenticate flows.
	OperationUserId uuid.UUID       `json:"op_user_id,omitempty"`
	Metadata        SessionMetadata `json:"metadata,omitempty"`
}

type AuthTransitionStore interface {
	Create(ctx context.Context, provider string, store SessionStore) (AuthSession, error)
	Get(ctx context.Context, id uuid.UUID) (AuthSession, error)
	Update(ctx context.Context, id uuid.UUID, store SessionStore) error
	Delete(ctx context.Context, id uuid.UUID) error
}
