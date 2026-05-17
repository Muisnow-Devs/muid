package identity

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

const passkeyCreationPayloadKey = "credential_creation_response_json"

func verifyPasskeyCreationChallengeBinding(creationJSON, expectedChallengeB64 string) error {
	var outer struct {
		Response struct {
			ClientDataJSON string `json:"clientDataJSON"`
		} `json:"response"`
	}
	if err := json.Unmarshal([]byte(creationJSON), &outer); err != nil {
		return fmt.Errorf("creation json: %w", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(outer.Response.ClientDataJSON)
	if err != nil {
		return fmt.Errorf("clientDataJSON base64: %w", err)
	}
	var cd struct {
		Challenge string `json:"challenge"`
		Type      string `json:"type"`
	}
	if err := json.Unmarshal(raw, &cd); err != nil {
		return fmt.Errorf("client data: %w", err)
	}
	if cd.Type != "webauthn.create" {
		return errors.New("unexpected clientData type for registration")
	}
	if cd.Challenge != expectedChallengeB64 {
		return errors.New("webauthn challenge mismatch")
	}
	return nil
}

func extractCreationCredentialID(creationJSON string) ([]byte, error) {
	var outer struct {
		RawID string `json:"rawId"`
		ID    string `json:"id"`
	}
	if err := json.Unmarshal([]byte(creationJSON), &outer); err != nil {
		return nil, err
	}
	b64 := outer.RawID
	if b64 == "" {
		b64 = outer.ID
	}
	if b64 == "" {
		return nil, errors.New("missing rawId/id")
	}
	raw, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, errors.New("empty credential id")
	}
	return raw, nil
}

func extractAttestationObject(creationJSON string) ([]byte, error) {
	var outer struct {
		Response struct {
			AttestationObject string `json:"attestationObject"`
		} `json:"response"`
	}
	if err := json.Unmarshal([]byte(creationJSON), &outer); err != nil {
		return nil, err
	}
	if outer.Response.AttestationObject == "" {
		return nil, errors.New("missing attestationObject")
	}
	raw, err := base64.RawURLEncoding.DecodeString(outer.Response.AttestationObject)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, errors.New("empty attestationObject")
	}
	return raw, nil
}
