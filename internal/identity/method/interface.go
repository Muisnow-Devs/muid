package method

import (
	"context"

	"github.com/google/uuid"
	"sanzi.io/muid/api/proto/shared/v1/claims"
	"sanzi.io/muid/internal/identity/issuer"
	identitystore "sanzi.io/muid/internal/identity/store"
	"sanzi.io/muid/internal/session"
)

type StepKind string

const (
	StepKindChallenge StepKind = "challenge"
	StepKindRedirect  StepKind = "redirect"
	StepKindPending   StepKind = "pending"
	StepKindVerified  StepKind = "verified"
	StepKindFailure   StepKind = "failure"
)

type Step interface {
	StepKind() StepKind
}

type RequestPayload interface {
	PayloadKind() string
}

type StartRequest struct {
	Metadata   session.SessionMetadata
	Identifier string
	Intent     session.AuthIntent
	Session    *issuer.ResolvedSession
}

type ContinueRequest struct {
	TransitionId uuid.UUID
	Payload      RequestPayload
	Session      *issuer.ResolvedSession
}

type IdentityMethod interface {
	Name() string

	Start(
		ctx context.Context,
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
	Provider string
	Subject  string

	// UserClaims carries user-profile information (email, display name, …)
	// used by the resolver to find or create the user account.
	UserClaims *claims.IdentityInformation

	// IdentityClaims carries the method-specific data that the store needs to
	// persist the identity sub-table (e.g. PasskeyIdentityClaims). It is nil
	// when the identity is already known (login path where FindUser returns a
	// record).
	IdentityClaims identitystore.IdentityClaims

	// Store is the IdentityStore for this method. The handler calls FindUser
	// and LinkIdentity on it directly — no type switch needed.
	Store identitystore.IdentityStore
}
