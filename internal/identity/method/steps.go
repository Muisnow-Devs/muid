package method

import (
	"github.com/google/uuid"
	sessionpb "sanzi.io/muid/api/proto/authn/v1/session"
)

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

// FailureStep reports a failure in the auth flow.
// Exactly one of Failure or Err must be non-nil:
//   - Failure carries a pre-built AuthFailure proto for application-level errors
//     (wrong credentials, rate-limited, invalid input, …). The handler maps
//     Failure.ErrorCode to the appropriate gRPC status code and attaches Failure
//     as a typed gRPC error detail so clients can extract it via status.Details().
//   - Err signals a structural failure (session not-found, expired) that maps
//     directly to a gRPC status without an AuthFailure detail.
type FailureStep struct {
	Failure *sessionpb.AuthFailure
	Err     error
}

func (*FailureStep) StepKind() StepKind {
	return StepKindFailure
}

// newAuthFailure is a convenience constructor that follows the opaque API style
// for proto message construction.
func newAuthFailure(code sessionpb.AuthErrorCode, reason string) *sessionpb.AuthFailure {
	f := &sessionpb.AuthFailure{}
	f.SetErrorCode(code)
	f.SetReason(reason)
	return f
}
