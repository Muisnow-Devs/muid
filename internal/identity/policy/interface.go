package policy

import (
	"context"
)

type LinkDecision string

const (
	LinkDecisionAllow  LinkDecision = "allow"
	LinkDecisionReject LinkDecision = "reject"
)

// LinkRequest carries the identity coordinates to check for duplication.
type LinkRequest struct {
	Provider string
	Subject  string
}

// LinkPolicy decides whether an identity can be linked to a user.
type LinkPolicy interface {
	ValidateLink(ctx context.Context, req LinkRequest) (LinkDecision, error)
}
