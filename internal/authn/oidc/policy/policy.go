// Package policy is the single decision point for "may this user authenticate
// against this OIDC client with these scopes". It is consulted at
// authorize-time, consent-time, device-approval-time, device-code redemption,
// and refresh rotation so revoked access dies at the next touchpoint.
package policy

import (
	"context"
	"errors"
	"slices"

	"github.com/google/uuid"

	"sanzi.io/muid/internal/authn/ent"
	"sanzi.io/muid/internal/authn/ent/oidcclient"
)

var (
	// ErrClientDisabled indicates the client is deleted or unpublished
	// (maps to unauthorized_client).
	ErrClientDisabled = errors.New("oidc policy: client disabled")
	// ErrAccessDenied indicates the user fails the client's access policy
	// (maps to access_denied).
	ErrAccessDenied = errors.New("oidc policy: access denied")
	// ErrScopeNotAllowed indicates a requested scope is outside the client's
	// allowed scopes (maps to invalid_scope).
	ErrScopeNotAllowed = errors.New("oidc policy: scope not allowed")
)

// MembershipChecker answers organization membership questions (backed by the
// authz service).
type MembershipChecker interface {
	IsMember(ctx context.Context, organizationID, userID uuid.UUID) (bool, error)
}

// AllowlistChecker answers private-client allowlist questions.
type AllowlistChecker interface {
	HasAccess(ctx context.Context, clientRefID, userID uuid.UUID) (bool, error)
}

// Evaluator decides whether a user may authenticate against a client.
type Evaluator struct {
	membership MembershipChecker
	allowlist  AllowlistChecker
}

func NewEvaluator(membership MembershipChecker, allowlist AllowlistChecker) *Evaluator {
	return &Evaluator{
		membership: membership,
		allowlist:  allowlist,
	}
}

// ClientUsable rejects deleted or disabled clients.
func ClientUsable(client *ent.OIDCClient) error {
	if client == nil || client.DeletedAt != nil ||
		client.PublishStatus == oidcclient.PublishStatusDisabled {
		return ErrClientDisabled
	}
	return nil
}

// AuthorizeUser applies the full access decision for userID against client.
func (e *Evaluator) AuthorizeUser(
	ctx context.Context,
	client *ent.OIDCClient,
	userID uuid.UUID,
	requestedScopes []string,
) error {
	err := ClientUsable(client)
	if err != nil {
		return err
	}

	// Unpublished clients are only usable by members of the owning
	// organization, regardless of access policy.
	requireMembership := client.PublishStatus == oidcclient.PublishStatusDraft ||
		client.PublishStatus == oidcclient.PublishStatusTesting

	switch client.AccessPolicy {
	case oidcclient.AccessPolicyPublic:
		// Membership still gates unpublished clients below.
	case oidcclient.AccessPolicyOrganization:
		requireMembership = true
	case oidcclient.AccessPolicyPrivate:
		allowed, accessErr := e.allowlist.HasAccess(ctx, client.ID, userID)
		if accessErr != nil {
			return accessErr
		}
		if !allowed {
			return ErrAccessDenied
		}
	default:
		return ErrAccessDenied
	}

	if requireMembership {
		isMember, memberErr := e.membership.IsMember(ctx, client.OwnerOrganizationID, userID)
		if memberErr != nil {
			return memberErr
		}
		if !isMember {
			return ErrAccessDenied
		}
	}

	return ScopesAllowed(client.Scopes, requestedScopes)
}

// ScopesAllowed verifies requested is a subset of allowed.
func ScopesAllowed(allowed, requested []string) error {
	for _, scope := range requested {
		if !slices.Contains(allowed, scope) {
			return ErrScopeNotAllowed
		}
	}
	return nil
}
