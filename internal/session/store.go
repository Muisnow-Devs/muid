package session

import "encoding/json"

// AuthStep is the transition lifecycle step for [SessionStore].
type AuthStep string

const (
	StepUnspecified AuthStep = ""
	StepStart       AuthStep = "start"
	StepContinue    AuthStep = "continue"
	// StepRegister awaits login-flow provision from provider register-required outcome.
	StepRegister AuthStep = "register"
	// StepFinish is a legacy constant retained for JSON backwards-compatibility.
	StepFinish AuthStep = "finish"
)

// FlowState holds flow-specific transition payloads; [Kind] selects the active branch.
type FlowState struct {
	Kind AuthFlowKind `json:"kind"`

	Email   *EmailOTPFlow `json:"email,omitempty"`
	OIDC    *OIDCFlow     `json:"oidc,omitempty"`
	Passkey *PasskeyFlow  `json:"passkey,omitempty"`
}

// EmailFlow returns the email OTP payload when Kind is [FlowKindEmailOTP].
func (s SessionStore) EmailFlow() (*EmailOTPFlow, bool) {
	if s.Flow.Kind != FlowKindEmailOTP || s.Flow.Email == nil {
		return nil, false
	}
	return s.Flow.Email, true
}

// OIDCFlowState returns the OIDC payload when Kind is [FlowKindOIDC].
func (s SessionStore) OIDCFlowState() (*OIDCFlow, bool) {
	if s.Flow.Kind != FlowKindOIDC || s.Flow.OIDC == nil {
		return nil, false
	}
	return s.Flow.OIDC, true
}

// PasskeyFlowState returns the passkey payload when Kind is [FlowKindPasskey].
func (s SessionStore) PasskeyFlowState() (*PasskeyFlow, bool) {
	if s.Flow.Kind != FlowKindPasskey || s.Flow.Passkey == nil {
		return nil, false
	}
	return s.Flow.Passkey, true
}

// EmailOTPStore builds a store for an email OTP transition.
func EmailOTPStore(step AuthStep, email *EmailOTPFlow) SessionStore {
	return SessionStore{
		Step: step,
		Flow: FlowState{Kind: FlowKindEmailOTP, Email: email},
	}
}

// OIDCStore builds a store for an OIDC transition.
func OIDCStore(step AuthStep, oidc *OIDCFlow) SessionStore {
	return SessionStore{
		Step: step,
		Flow: FlowState{Kind: FlowKindOIDC, OIDC: oidc},
	}
}

// PasskeyStore builds a store for a passkey transition.
func PasskeyStore(step AuthStep, passkey *PasskeyFlow) SessionStore {
	return SessionStore{
		Step: step,
		Flow: FlowState{Kind: FlowKindPasskey, Passkey: passkey},
	}
}

// UnmarshalJSON accepts the nested flow object and legacy top-level flow kind + payloads.
func (s *SessionStore) UnmarshalJSON(data []byte) error {
	var raw struct {
		Attempts int      `json:"attempts"`
		Step     AuthStep `json:"step"`

		Flow json.RawMessage `json:"flow"`

		Locale    string `json:"locale,omitempty"`
		Timezone  string `json:"timezone,omitempty"`
		Device    string `json:"device,omitempty"`
		Location  string `json:"location,omitempty"`
		UserAgent string `json:"user_agent,omitempty"`
		IPAddress string `json:"ip_address,omitempty"`

		AuthIntent      string `json:"auth_intent,omitempty"`
		LinkUserID      string `json:"link_user_id,omitempty"`
		LinkSessionWire string `json:"link_session_wire,omitempty"`

		PendingRegister *RegisterPending `json:"pending_register,omitempty"`

		Email   *EmailOTPFlow `json:"email,omitempty"`
		OIDC    *OIDCFlow     `json:"oidc,omitempty"`
		Passkey *PasskeyFlow  `json:"passkey,omitempty"`
	}
	err := json.Unmarshal(data, &raw)
	if err != nil {
		return err
	}

	s.Attempts = raw.Attempts
	s.Step = raw.Step
	s.Locale = raw.Locale
	s.Timezone = raw.Timezone
	s.Device = raw.Device
	s.Location = raw.Location
	s.UserAgent = raw.UserAgent
	s.IPAddress = raw.IPAddress
	s.AuthIntent = raw.AuthIntent
	s.LinkUserID = raw.LinkUserID
	s.LinkSessionWire = raw.LinkSessionWire
	s.PendingRegister = raw.PendingRegister

	if len(raw.Flow) == 0 {
		return nil
	}

	var kindStr string
	if err := json.Unmarshal(raw.Flow, &kindStr); err == nil {
		s.Flow.Kind = AuthFlowKind(kindStr)
		s.Flow.Email = raw.Email
		s.Flow.OIDC = raw.OIDC
		s.Flow.Passkey = raw.Passkey
		return nil
	}

	return json.Unmarshal(raw.Flow, &s.Flow)
}
