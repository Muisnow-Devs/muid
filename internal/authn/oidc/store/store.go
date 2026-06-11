// Package store holds the short-lived OIDC protocol state (authorization
// codes, pending authorizations awaiting consent, device codes) in a KV
// backend. Redis TTLs are the source of truth for expiry.
package store

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
)

var (
	// ErrNotFound indicates the record does not exist, expired, or was
	// already consumed.
	ErrNotFound = errors.New("oidc store: record not found")
	// ErrConflict indicates a key collision while creating a record.
	ErrConflict = errors.New("oidc store: record already exists")
)

// RandomToken returns byteLen random bytes as raw-base64url text.
func RandomToken(byteLen int) (string, error) {
	buf := make([]byte, byteLen)
	_, err := rand.Read(buf)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// userCodeAlphabet avoids visually ambiguous characters (0/O, 1/I/L, U/V
// confusion per RFC 8628 §6.1 recommendations).
const userCodeAlphabet = "ABCDEFGHJKMNPQRSTVWXYZ23456789"

const userCodeLength = 8

// randomUserCode returns an 8-character code from userCodeAlphabet, stored
// and compared in this normalized form; UIs display it as XXXX-XXXX.
func randomUserCode() (string, error) {
	buf := make([]byte, userCodeLength)
	_, err := rand.Read(buf)
	if err != nil {
		return "", err
	}
	out := make([]byte, userCodeLength)
	for i, b := range buf {
		out[i] = userCodeAlphabet[int(b)%len(userCodeAlphabet)]
	}
	return string(out), nil
}
