package session

import (
	"context"
	"encoding/json"
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

// AuthFlowKind discriminates which flow payload is active in [SessionStore].
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
}

// OIDCFlow holds OIDC/PKCE transition state.
type OIDCFlow struct {
	OAuthState       string `json:"oauth_state"`
	PKCECodeVerifier string `json:"pkce_code_verifier"`
}

// PasskeyFlow holds WebAuthn ceremony state for the passkey login transition.
type PasskeyFlow struct {
	ChallengeB64 string `json:"challenge_b64"`
	RPID         string `json:"rp_id"`
}

type SessionStore struct {
	Attempts int    `json:"attempts"`
	Step     string `json:"step"`

	Flow AuthFlowKind `json:"flow"`

	Email   *EmailOTPFlow `json:"email,omitempty"`
	OIDC    *OIDCFlow     `json:"oidc,omitempty"`
	Passkey *PasskeyFlow  `json:"passkey,omitempty"`
}

type AuthTransitionStore interface {
	Create(ctx context.Context, provider string, store SessionStore) (AuthSession, error)
	Get(ctx context.Context, id string) (AuthSession, error)
	Update(ctx context.Context, id string, store SessionStore) error
	Delete(ctx context.Context, id string) error
}
