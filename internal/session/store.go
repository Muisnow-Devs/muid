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

// MarshalJSON serializes the SessionStore, nesting Flow as FlowJSON for backwards compatibility.
func (s SessionStore) MarshalJSON() ([]byte, error) {
	type Alias SessionStore
	var flowKind string
	var email *EmailOTPFlow
	var oidc *OIDCFlow
	var passkey *PasskeyFlow

	if s.Flow != nil {
		flowKind = s.Flow.PayloadKind()
		switch f := s.Flow.(type) {
		case *EmailOTPFlow:
			email = f
		case *OIDCFlow:
			oidc = f
		case *PasskeyFlow:
			passkey = f
		}
	}

	type FlowJSON struct {
		Kind    string        `json:"kind"`
		Email   *EmailOTPFlow `json:"email,omitempty"`
		OIDC    *OIDCFlow     `json:"oidc,omitempty"`
		Passkey *PasskeyFlow  `json:"passkey,omitempty"`
	}

	return json.Marshal(&struct {
		Alias
		Flow FlowJSON `json:"flow"`
	}{
		Alias: Alias(s),
		Flow: FlowJSON{
			Kind:    flowKind,
			Email:   email,
			OIDC:    oidc,
			Passkey: passkey,
		},
	})
}

// UnmarshalJSON accepts the nested flow object and legacy top-level flow kind + payloads.
func (s *SessionStore) UnmarshalJSON(data []byte) error {
	type Alias SessionStore
	var raw struct {
		Alias
		Flow json.RawMessage `json:"flow"`

		// Retain support for legacy fields
		Email   *EmailOTPFlow `json:"email,omitempty"`
		OIDC    *OIDCFlow     `json:"oidc,omitempty"`
		Passkey *PasskeyFlow  `json:"passkey,omitempty"`
	}

	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	*s = SessionStore(raw.Alias)

	if len(raw.Flow) == 0 {
		return nil
	}

	// The flow field might be an object
	var flowObj struct {
		Kind    string        `json:"kind"`
		Email   *EmailOTPFlow `json:"email,omitempty"`
		OIDC    *OIDCFlow     `json:"oidc,omitempty"`
		Passkey *PasskeyFlow  `json:"passkey,omitempty"`
	}

	if err := json.Unmarshal(raw.Flow, &flowObj); err == nil && flowObj.Kind != "" {
		switch flowObj.Kind {
		case "email_otp":
			s.Flow = flowObj.Email
		case "oidc":
			s.Flow = flowObj.OIDC
		case "passkey":
			s.Flow = flowObj.Passkey
		}
		return nil
	}

	// Fallback to legacy string kind
	var kindStr string
	if err := json.Unmarshal(raw.Flow, &kindStr); err == nil && kindStr != "" {
		switch kindStr {
		case "email_otp":
			s.Flow = raw.Email
		case "oidc":
			s.Flow = raw.OIDC
		case "passkey":
			s.Flow = raw.Passkey
		}
	}

	return nil
}
