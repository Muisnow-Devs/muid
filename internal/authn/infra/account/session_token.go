package account

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

const (
	SelectorLength  = 16
	ValidatorLength = 32

	SelectorB64Length  = (SelectorLength*8 + 5) / 6  // base64.RawURLEncoding.EncodedLen(SelectorLength)
	ValidatorB64Length = (ValidatorLength*8 + 5) / 6 // base64.RawURLEncoding.EncodedLen(ValidatorLength)

	// SessionTokenLength is the length of the full session token string, including the dot separator.
	SessionTokenLength = SelectorB64Length + 1 + ValidatorB64Length
)

var errInvalidSessionToken = errors.New("invalid session token format")

// ParseSessionToken splits a wire token into selector and validator segments.
func ParseSessionToken(wire string) (selectorB64, validatorB64 string, err error) {
	wire = strings.TrimSpace(wire)
	parts := strings.Split(wire, ".")
	if len(parts) != 2 {
		return "", "", errInvalidSessionToken
	}
	selectorB64 = parts[0]
	validatorB64 = parts[1]
	if len(selectorB64) != SelectorB64Length || len(validatorB64) != ValidatorB64Length {
		return "", "", fmt.Errorf("%w: unexpected segment lengths", errInvalidSessionToken)
	}
	if _, err := base64.RawURLEncoding.DecodeString(selectorB64); err != nil {
		return "", "", errors.Join(errInvalidSessionToken, err)
	}
	if _, err := base64.RawURLEncoding.DecodeString(validatorB64); err != nil {
		return "", "", errors.Join(errInvalidSessionToken, err)
	}
	return selectorB64, validatorB64, nil
}

func decodeSelector(selectorB64 string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(selectorB64)
	if err != nil {
		return nil, errors.Join(errInvalidSessionToken, err)
	}
	if len(raw) != SelectorLength {
		return nil, fmt.Errorf("%w: selector length %d", errInvalidSessionToken, len(raw))
	}
	return raw, nil
}

func decodeValidatorSecret(validatorB64 string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(validatorB64)
	if err != nil {
		return nil, errors.Join(errInvalidSessionToken, err)
	}
	if len(raw) != ValidatorLength {
		return nil, fmt.Errorf("%w: validator length %d", errInvalidSessionToken, len(raw))
	}
	return raw, nil
}
