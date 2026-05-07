package identity

import (
	"context"

	"sanzi.io/muid/internal/identity"
	"sanzi.io/muid/internal/session"
)

type PasskeyProvider struct {
	transitionStore session.AuthTransitionStore
}

func NewPasskeyIdentityProvider(
	transitionStore session.AuthTransitionStore,
) identity.IdentityProvider {
	return &PasskeyProvider{
		transitionStore: transitionStore,
	}
}

func (p *PasskeyProvider) Name() string {
	return "passkey"
}

func (p *PasskeyProvider) Continue(
	ctx context.Context,
	input identity.ContinueInput,
) (identity.StepResult, error) {
	panic("unimplemented")
}

func (p *PasskeyProvider) Start(
	ctx context.Context,
	input identity.StartInput,
) (identity.StepResult, error) {
	panic("unimplemented")
}
