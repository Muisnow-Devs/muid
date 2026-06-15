// Package csrf issues and validates stateless HMAC-signed CSRF tokens for
// mutating routes. Tokens are self-describing (random id + expiry + HMAC) so no
// server-side storage is needed; validation is a constant-time signature check.
package csrf

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"time"
)

var (
	// ErrInvalidToken is returned for malformed or tampered tokens.
	ErrInvalidToken = errors.New("csrf: invalid token")
	// ErrExpiredToken is returned for structurally valid but expired tokens.
	ErrExpiredToken = errors.New("csrf: expired token")
	// ErrMissingKey is returned when constructing a Manager without a key.
	ErrMissingKey = errors.New("csrf: signing key required")
)

// Manager signs and verifies CSRF tokens with a shared secret.
type Manager struct {
	key []byte
	ttl time.Duration
}

// New builds a Manager. key must be non-empty; ttl<=0 defaults to 12h.
func New(key []byte, ttl time.Duration) (*Manager, error) {
	if len(key) == 0 {
		return nil, ErrMissingKey
	}
	if ttl <= 0 {
		ttl = 12 * time.Hour
	}
	dup := make([]byte, len(key))
	copy(dup, key)
	return &Manager{key: dup, ttl: ttl}, nil
}

// Generate returns a fresh token valid for the manager's TTL.
func (m *Manager) Generate() (string, error) {
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return "", err
	}
	id := base64.RawURLEncoding.EncodeToString(idBytes)
	exp := strconv.FormatInt(time.Now().Add(m.ttl).Unix(), 10)
	payload := id + "." + exp
	sig := m.sign(payload)
	return payload + "." + sig, nil
}

// Validate checks the token's signature and expiry.
func (m *Manager) Validate(token string) error {
	token = strings.TrimSpace(token)
	id, rest, ok := strings.Cut(token, ".")
	if !ok {
		return ErrInvalidToken
	}
	expStr, sig, ok := strings.Cut(rest, ".")
	if !ok {
		return ErrInvalidToken
	}

	payload := id + "." + expStr
	expected := m.sign(payload)
	if !hmac.Equal([]byte(sig), []byte(expected)) {
		return ErrInvalidToken
	}

	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil {
		return ErrInvalidToken
	}
	if time.Now().After(time.Unix(exp, 0)) {
		return ErrExpiredToken
	}
	return nil
}

func (m *Manager) sign(payload string) string {
	mac := hmac.New(sha256.New, m.key)
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
