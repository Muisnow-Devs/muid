package method

import (
	"context"

	"github.com/google/uuid"
	"sanzi.io/muid/api/proto/shared/v1/claims"
	"sanzi.io/muid/internal/identity/issuer"
	identitystore "sanzi.io/muid/internal/identity/store"
	"sanzi.io/muid/internal/session"
)

// StepKind identifies the kind of step returned by a method.
type StepKind string

const (
	StepKindChallenge StepKind = "challenge"
	StepKindRedirect  StepKind = "redirect"
	StepKindPending   StepKind = "pending"
	StepKindVerified  StepKind = "verified"
	StepKindFailure   StepKind = "failure"
)

// Step is the sealed interface for the outcomes returned by a method.
type Step interface {
	StepKind() StepKind
}

// RequestPayload is the sealed interface for step continuation payloads.
type RequestPayload interface {
	PayloadKind() string
}

// StartRequest carries the caller-provided identifier used to start a method.
type StartRequest struct {
	Identifier string
}

// ContinueRequest carries the transition being continued and its payload.
type ContinueRequest struct {
	TransitionID uuid.UUID
	Payload      RequestPayload
	Session      *issuer.ResolvedSession
}

// IdentityMethod drives one authentication or linking method.
type IdentityMethod interface {
	Name() string

	Start(
		ctx context.Context,
		sessionStore session.SessionStore,
		req StartRequest,
	) (Step, error)

	Continue(
		ctx context.Context,
		req ContinueRequest,
	) (Step, error)
}

// VerifiedIdentity is the resolved identity returned by a method after
// successful verification.
type VerifiedIdentity struct {
	// UserClaims carries user-profile information (email, display name, …)
	// used by the resolver to find or create the user account.
	UserClaims *claims.IdentityInformation

	// IdentityClaims carries the method-specific data that the store needs to
	// persist the identity sub-table (e.g. PasskeyIdentityClaims). It is nil
	// when the identity is already known (login path where FindUser returns a
	// record).
	IdentityClaims identitystore.IdentityClaims
}
