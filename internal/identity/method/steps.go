package method

import "github.com/google/uuid"

// Challenge
type ChallengeStep struct {
	TransitionId uuid.UUID
	Challenge    any
}

func (c ChallengeStep) StepKind() StepKind {
	return StepKindChallenge
}

// Redirect
type RedirectStep struct {
	TransitionId uuid.UUID
	RedirectURL  string
}

func (r RedirectStep) StepKind() StepKind {
	return StepKindRedirect
}

// Pending
type PendingStep struct {
	SessionID string
	Message   string
}

func (*PendingStep) StepKind() StepKind {
	return StepKindPending
}

// Verified
type VerifiedStep struct {
	Provider string
	Subject  string

	Identity VerifiedIdentity
}

func (*VerifiedStep) StepKind() StepKind {
	return StepKindVerified
}

// Failure
type FailureStep struct {
	Code    string
	Message string

	Err error
}

func (*FailureStep) StepKind() StepKind {
	return StepKindFailure
}
