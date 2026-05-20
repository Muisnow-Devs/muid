package session

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

const (
	SelectorByteLength  = 16
	ValidatorByteLength = 32

	// SelectorB64Length is the RawURLEncoding length for a 16-byte selector.
	SelectorB64Length = (SelectorByteLength*8 + 5) / 6
	// ValidatorB64Length is the RawURLEncoding length for a 32-byte validator secret.
	ValidatorB64Length = (ValidatorByteLength*8 + 5) / 6

	// WireSessionTokenLength is the full wire token length including the dot separator.
	WireSessionTokenLength = SelectorB64Length + 1 + ValidatorB64Length
)

// ParseWireSessionToken splits a wire session token into base64url selector and validator segments.
func ParseWireSessionToken(wire string) (selectorB64, validatorB64 string, err error) {
	wire = strings.TrimSpace(wire)
	parts := strings.Split(wire, ".")
	if len(parts) != 2 {
		return "", "", ErrInvalidWireSessionToken
	}
	selectorB64 = parts[0]
	validatorB64 = parts[1]
	if len(selectorB64) != SelectorB64Length || len(validatorB64) != ValidatorB64Length {
		return "", "", fmt.Errorf("%w: unexpected segment lengths", ErrInvalidWireSessionToken)
	}
	if _, err := base64.RawURLEncoding.DecodeString(selectorB64); err != nil {
		return "", "", errors.Join(ErrInvalidWireSessionToken, err)
	}
	if _, err := base64.RawURLEncoding.DecodeString(validatorB64); err != nil {
		return "", "", errors.Join(ErrInvalidWireSessionToken, err)
	}
	return selectorB64, validatorB64, nil
}

// DecodeWireSelectorBytes decodes the selector segment to raw bytes.
func DecodeWireSelectorBytes(selectorB64 string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(selectorB64)
	if err != nil {
		return nil, errors.Join(ErrInvalidWireSessionToken, err)
	}
	if len(raw) != SelectorByteLength {
		return nil, fmt.Errorf("%w: selector length %d", ErrInvalidWireSessionToken, len(raw))
	}
	return raw, nil
}

// DecodeWireValidatorSecret decodes the validator segment to the raw 32-byte secret.
func DecodeWireValidatorSecret(validatorB64 string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(validatorB64)
	if err != nil {
		return nil, errors.Join(ErrInvalidWireSessionToken, err)
	}
	if len(raw) != ValidatorByteLength {
		return nil, fmt.Errorf("%w: validator length %d", ErrInvalidWireSessionToken, len(raw))
	}
	return raw, nil
}
