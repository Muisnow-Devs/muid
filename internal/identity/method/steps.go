package method

import "github.com/google/uuid"

// ChallengeStep asks the caller to present a challenge to the user.
type ChallengeStep struct {
	TransitionID uuid.UUID
	Challenge    any
}

func (c ChallengeStep) StepKind() StepKind {
	return StepKindChallenge
}

// RedirectStep asks the caller to redirect the user.
type RedirectStep struct {
	TransitionID uuid.UUID
	RedirectURL  string
}

func (r RedirectStep) StepKind() StepKind {
	return StepKindRedirect
}

// PendingStep tells the caller that the flow is waiting on another action.
type PendingStep struct {
	SessionID string
	Message   string
}

func (*PendingStep) StepKind() StepKind {
	return StepKindPending
}

// VerifiedStep carries a successfully verified identity.
type VerifiedStep struct {
	Provider string
	Subject  string

	Identity VerifiedIdentity
}

func (*VerifiedStep) StepKind() StepKind {
	return StepKindVerified
}

// FailureStep reports a user-visible failure.
type FailureStep struct {
	Code    string
	Message string

	Err error
}

func (*FailureStep) StepKind() StepKind {
	return StepKindFailure
}
