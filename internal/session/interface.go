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
	Attempts int

	// flow based fields
	State string // OAuth state
	Step  string // Current step in the authentication flow

	Data []byte

	LoginHint string

	CreatedAt int64
	UpdatedAt int64
	ExpiresAt int64
}

type AuthTransitionStore interface {
	Create(ctx context.Context, session AuthSession) (AuthSession, error)
	Get(ctx context.Context, provider, id string) (AuthSession, error)
	Update(ctx context.Context, session AuthSession) error
	Delete(ctx context.Context, provider, id string) error
	Close()
}
