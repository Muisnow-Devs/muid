package policy

import (
	"context"
	"slices"

	"github.com/google/uuid"

	authzevent "sanzi.io/muid/api/proto/event/v1/authz"
	authzent "sanzi.io/muid/internal/authz/ent"
	"sanzi.io/muid/internal/authz/ent/casbinrule"
	"sanzi.io/muid/internal/authz/ent/organizationmember"
	"sanzi.io/muid/internal/authz/ent/organizationrole"
	"sanzi.io/muid/pkg/enttx"
	"sanzi.io/muid/pkg/log"
)

// CreateOrganization creates an organization, seeds its system roles, and
// adds the first owner — all in one transaction.
func (m *Manager) CreateOrganization(
	ctx context.Context,
	name, description, domain string,
	ownerUserID uuid.UUID,
) (uuid.UUID, error) {
	type txOut struct {
		orgID    uuid.UUID
		grouping Rule
		revision uuid.UUID
	}
	out, err := enttx.Run(ctx, m.db.Tx,
		func(ctx context.Context, tx *authzent.Tx) (txOut, error) {
			org, err := tx.Organization.Create().
				SetName(name).
				SetDescription(description).
				SetDomain(domain).
				Save(ctx)
			if authzent.IsConstraintError(err) {
				return txOut{}, ErrOrganizationExists
			}
			if err != nil {
				return txOut{}, err
			}

			ownerRoleID := uuid.Nil
			for _, roleName := range m.cfg.SystemRoles {
				role, err := tx.OrganizationRole.Create().
					SetOrganizationID(org.ID).
					SetName(roleName).
					SetIsSystem(true).
					Save(ctx)
				if err != nil {
					return txOut{}, err
				}
				if roleName == RoleOwner {
					ownerRoleID = role.ID
				}
			}

			err = ensureUserRef(ctx, tx, ownerUserID)
			if err != nil {
				return txOut{}, err
			}
			_, err = tx.OrganizationMember.Create().
				SetOrganizationID(org.ID).
				SetUserID(ownerUserID).
				SetRoleID(ownerRoleID).
				Save(ctx)
			if err != nil {
				return txOut{}, err
			}

			grouping := membershipRule(ownerUserID, RoleOwner, org.ID.String())
			err = insertRules(ctx, tx.CasbinRule, []Rule{grouping})
			if err != nil {
				return txOut{}, err
			}
			rev, err := bumpRevision(ctx, tx)
			if err != nil {
				return txOut{}, err
			}
			return txOut{orgID: org.ID, grouping: grouping, revision: rev}, nil
		})
	if err != nil {
		return uuid.Nil, err
	}

	m.memoryAddRules(ctx, []Rule{out.grouping})
	m.publishChange(ctx, policyChange{
		kind:     authzevent.PolicyChangeKind_POLICY_CHANGE_KIND_MEMBERSHIP_CHANGED,
		orgID:    out.orgID,
		role:     RoleOwner,
		userID:   ownerUserID,
		revision: out.revision,
	})
	return out.orgID, nil
}

// DeleteOrganization removes the organization with its members, roles, and
// every casbin rule scoped to it.
func (m *Manager) DeleteOrganization(ctx context.Context, organizationID uuid.UUID) error {
	err := m.requireOrganization(ctx, organizationID)
	if err != nil {
		return err
	}

	domain := organizationID.String()

	rev, err := enttx.Run(ctx, m.db.Tx,
		func(ctx context.Context, tx *authzent.Tx) (uuid.UUID, error) {
			_, err := tx.OrganizationMember.Delete().
				Where(organizationmember.OrganizationID(organizationID)).
				Exec(ctx)
			if err != nil {
				return uuid.Nil, err
			}
			_, err = tx.OrganizationRole.Delete().
				Where(organizationrole.OrganizationID(organizationID)).
				Exec(ctx)
			if err != nil {
				return uuid.Nil, err
			}
			err = tx.Organization.DeleteOneID(organizationID).Exec(ctx)
			if err != nil {
				return uuid.Nil, err
			}
			_, err = tx.CasbinRule.Delete().
				Where(casbinrule.Or(
					casbinrule.And(casbinrule.Ptype("p"), casbinrule.V1(domain)),
					casbinrule.And(casbinrule.Ptype("g"), casbinrule.V2(domain)),
				)).
				Exec(ctx)
			if err != nil {
				return uuid.Nil, err
			}
			return bumpRevision(ctx, tx)
		})
	if err != nil {
		return err
	}

	_, err = m.enforcer.RemoveFilteredPolicy(1, domain)
	if err != nil {
		log.LogUnexpected(ctx, "authz enforcer delta after org delete", err.Error())
	}
	_, err = m.enforcer.RemoveFilteredGroupingPolicy(2, domain)
	if err != nil {
		log.LogUnexpected(ctx, "authz enforcer delta after org delete", err.Error())
	}
	m.publishChange(ctx, policyChange{
		kind:     authzevent.PolicyChangeKind_POLICY_CHANGE_KIND_ORGANIZATION_DELETED,
		orgID:    organizationID,
		revision: rev,
	})
	return nil
}

// AddRawRules writes verbatim casbin rules (internal admin escape hatch).
func (m *Manager) AddRawRules(ctx context.Context, rules []Rule) error {
	err := validateRawRules(rules)
	if err != nil {
		return err
	}

	rev, err := enttx.Run(ctx, m.db.Tx,
		func(ctx context.Context, tx *authzent.Tx) (uuid.UUID, error) {
			err := insertRules(ctx, tx.CasbinRule, rules)
			if authzent.IsConstraintError(err) {
				return uuid.Nil, ErrInvalidRule
			}
			if err != nil {
				return uuid.Nil, err
			}
			return bumpRevision(ctx, tx)
		})
	if err != nil {
		return err
	}

	m.memoryAddRules(ctx, rules)
	m.publishChange(ctx, policyChange{
		kind:     authzevent.PolicyChangeKind_POLICY_CHANGE_KIND_ROLE_GRANTS_CHANGED,
		revision: rev,
	})
	return nil
}

// RemoveRawRules deletes verbatim casbin rules; missing rules are ignored.
func (m *Manager) RemoveRawRules(ctx context.Context, rules []Rule) error {
	err := validateRawRules(rules)
	if err != nil {
		return err
	}

	rev, err := enttx.Run(ctx, m.db.Tx,
		func(ctx context.Context, tx *authzent.Tx) (uuid.UUID, error) {
			for _, r := range rules {
				_, err := deleteRule(ctx, tx.CasbinRule, r)
				if err != nil {
					return uuid.Nil, err
				}
			}
			return bumpRevision(ctx, tx)
		})
	if err != nil {
		return err
	}

	m.memoryRemoveRules(ctx, rules)
	m.publishChange(ctx, policyChange{
		kind:     authzevent.PolicyChangeKind_POLICY_CHANGE_KIND_ROLE_GRANTS_CHANGED,
		revision: rev,
	})
	return nil
}

// validateRawRules checks rule shapes: p-rules carry [sub, dom, obj, act],
// g-rules [member, role, dom].
func validateRawRules(rules []Rule) error {
	for _, r := range rules {
		switch r.Ptype {
		case "p":
			if len(r.Values) != 4 {
				return ErrInvalidRule
			}
		case "g":
			if len(r.Values) != 3 {
				return ErrInvalidRule
			}
		default:
			return ErrInvalidRule
		}
		if slices.Contains(r.Values, "") {
			return ErrInvalidRule
		}
	}
	return nil
}
