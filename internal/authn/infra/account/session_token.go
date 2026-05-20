package account

import (
	"sanzi.io/muid/internal/session"
)

// Wire session token layout (delegates to [session] package).
const (
	SelectorLength     = session.SelectorByteLength
	ValidatorLength    = session.ValidatorByteLength
	SelectorB64Length  = session.SelectorB64Length
	ValidatorB64Length = session.ValidatorB64Length
	SessionTokenLength = session.WireSessionTokenLength
)

// ParseSessionToken splits a wire token into selector and validator segments.
func ParseSessionToken(wire string) (selectorB64, validatorB64 string, err error) {
	return session.ParseWireSessionToken(wire)
}

func decodeSelector(selectorB64 string) ([]byte, error) {
	return session.DecodeWireSelectorBytes(selectorB64)
}

func decodeValidatorSecret(validatorB64 string) ([]byte, error) {
	return session.DecodeWireValidatorSecret(validatorB64)
}
