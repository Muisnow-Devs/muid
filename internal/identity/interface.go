package identity

import (
	"context"

	"sanzi.io/muid/api/proto/authn/v1/session"
)

type StepType string

const (
	StepRedirect  StepType = "redirect"
	StepInput     StepType = "input"
	StepChallenge StepType = "challenge"
	StepComplete  StepType = "complete"
)

type StartInput struct {
	Provider   string
	Identifier string
	Metadata   map[string]any
}

type ContinueInput struct {
	TransitionId string
	Payload      map[string]any
}

type StepResult struct {
	TransitionId string

	Type        StepType
	RedirectURL string // Optional, for OIDC flows

	Challenge      any // Optional, for challenge-based flows (e.g. WebAuthn)
	RequiredFields []string

	AuthenticatedResult *session.AuthenticatedResult // Optional, for complete steps
}

type IdentityProvider interface {
	Name() string
	Start(ctx context.Context, input StartInput) (StepResult, error)
	Continue(ctx context.Context, input ContinueInput) (StepResult, error)
}
