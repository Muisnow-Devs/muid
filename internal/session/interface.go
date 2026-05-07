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

type SessionStore struct {
	Attempts int

	// flow based fields
	State        string // OAuth state
	Step         string // Current step in the authentication flow
	CodeVerifier string // PKCE code verifier

	Data []byte

	LoginHint string
}

type AuthTransitionStore interface {
	Create(ctx context.Context, provider string, store SessionStore) (AuthSession, error)
	Get(ctx context.Context, id string) (AuthSession, error)
	Update(ctx context.Context, id string, store SessionStore) error
	Delete(ctx context.Context, id string) error
}
