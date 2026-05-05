package identity

import (
	"context"
)

type StepType string

const (
	StepRedirect  StepType = "redirect"
	StepInput     StepType = "input"
	StepChallenge StepType = "challenge"
	StepComplete  StepType = "complete"
)

type StartInput struct {
	LoginHint   string
	RedirectURI string
	Metadata    map[string]any
}

type ContinueInput struct {
	TransactionID string
	Payload       map[string]any
}

type StepResult struct {
	TransactionID string

	Type        StepType
	RedirectURL string // Optional, for OIDC flows

	Challenge      any // Optional, for challenge-based flows (e.g. WebAuthn)
	RequiredFields []string

	// Session *
}

type IdentityProvider interface {
	Name() string
	Start(ctx context.Context, input StartInput) (StepResult, error)
	Continue(ctx context.Context, input ContinueInput) (StepResult, error)
}
