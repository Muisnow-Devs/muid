package policy

import (
	"context"

	"sanzi.io/muid/internal/authn/ent"
	"sanzi.io/muid/internal/authn/ent/useridentity"
)

// EntLinkPolicy is the Ent-backed LinkPolicy.
type EntLinkPolicy struct {
	db *ent.Client
}

func NewEntLinkPolicy(db *ent.Client) LinkPolicy {
	return &EntLinkPolicy{db: db}
}

// ValidateLink checks whether the given provider+subject identity is available
// for linking. An identity is available only when no active (non-revoked) row
// exists — it does not matter which user currently owns it.
func (p *EntLinkPolicy) ValidateLink(
	ctx context.Context,
	req LinkRequest,
) (LinkDecision, error) {
	exists, err := p.db.UserIdentity.Query().
		Where(
			useridentity.ProviderEQ(req.Provider),
			useridentity.SubjectEQ(req.Subject),
			useridentity.RevokedAtIsNil(),
		).
		Exist(ctx)
	if err != nil {
		return "", err
	}
	if exists {
		return LinkDecisionReject, nil
	}

	return LinkDecisionAllow, nil
}
