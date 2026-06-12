package policy

import (
	"context"
	"strings"

	"github.com/google/uuid"

	authzevent "sanzi.io/muid/api/proto/event/v1/authz"
	authzent "sanzi.io/muid/internal/authz/ent"
	"sanzi.io/muid/internal/authz/ent/casbinrule"
	"sanzi.io/muid/internal/authz/ent/organizationrole"
	"sanzi.io/muid/pkg/enttx"
	"sanzi.io/muid/pkg/shared/authzmodel"
)

// Reconcile brings the wildcard-domain casbin rules in line with the static
// configuration (insert missing, delete stale) and backfills missing system
// OrganizationRole rows for existing organizations. It is idempotent and
// runs at startup and on the ReloadPolicyConfig admin RPC.
func (m *Manager) Reconcile(ctx context.Context) (changed bool, revision uuid.UUID, err error) {
	desired, err := m.cfg.WildcardRules()
	if err != nil {
		return false, uuid.Nil, err
	}
	desiredKeys := make(map[string]Rule, len(desired))
	for _, r := range desired {
		desiredKeys[ruleKey(r)] = r
	}

	actualRows, err := m.db.CasbinRule.Query().
		Where(casbinrule.Or(
			casbinrule.And(
				casbinrule.Ptype("p"),
				casbinrule.V1(authzmodel.WildcardDomain),
			),
			casbinrule.And(
				casbinrule.Ptype("g"),
				casbinrule.V2(authzmodel.WildcardDomain),
			),
		)).
		All(ctx)
	if err != nil {
		return false, uuid.Nil, err
	}
	actualKeys := make(map[string]Rule, len(actualRows))
	for _, row := range actualRows {
		r := ruleFromRow(row)
		actualKeys[ruleKey(r)] = r
	}

	var toInsert, toDelete []Rule
	for key, r := range desiredKeys {
		if _, ok := actualKeys[key]; !ok {
			toInsert = append(toInsert, r)
		}
	}
	for key, r := range actualKeys {
		if _, ok := desiredKeys[key]; !ok {
			toDelete = append(toDelete, r)
		}
	}

	missingRoles, err := m.missingSystemRoles(ctx)
	if err != nil {
		return false, uuid.Nil, err
	}

	rulesChanged := len(toInsert) > 0 || len(toDelete) > 0
	if !rulesChanged && len(missingRoles) == 0 {
		revision, err = m.Revision(ctx)
		return false, revision, err
	}

	revision, err = enttx.Run(ctx, m.db.Tx,
		func(ctx context.Context, tx *authzent.Tx) (uuid.UUID, error) {
			err := insertRules(ctx, tx.CasbinRule, toInsert)
			if err != nil {
				return uuid.Nil, err
			}
			for _, r := range toDelete {
				_, err = deleteRule(ctx, tx.CasbinRule, r)
				if err != nil {
					return uuid.Nil, err
				}
			}
			for _, missing := range missingRoles {
				_, err = tx.OrganizationRole.Create().
					SetOrganizationID(missing.orgID).
					SetName(missing.name).
					SetIsSystem(true).
					Save(ctx)
				if err != nil {
					return uuid.Nil, err
				}
			}
			if !rulesChanged {
				return m.Revision(ctx)
			}
			return bumpRevision(ctx, tx)
		})
	if err != nil {
		return false, uuid.Nil, err
	}

	if rulesChanged {
		err = m.enforcer.LoadPolicy()
		if err != nil {
			return true, revision, err
		}
		m.publishChange(ctx, policyChange{
			kind:     authzevent.PolicyChangeKind_POLICY_CHANGE_KIND_CONFIG_RELOADED,
			revision: revision,
		})
	}
	return rulesChanged, revision, nil
}

// systemRoleBackfill is one missing (organization, system role) pair.
type systemRoleBackfill struct {
	orgID uuid.UUID
	name  string
}

// missingSystemRoles finds organizations lacking a system role row.
func (m *Manager) missingSystemRoles(ctx context.Context) ([]systemRoleBackfill, error) {
	orgIDs, err := m.db.Organization.Query().IDs(ctx)
	if err != nil {
		return nil, err
	}
	if len(orgIDs) == 0 {
		return nil, nil
	}

	rows, err := m.db.OrganizationRole.Query().
		Where(organizationrole.NameIn(m.cfg.SystemRoles...)).
		All(ctx)
	if err != nil {
		return nil, err
	}
	have := make(map[uuid.UUID]map[string]struct{}, len(orgIDs))
	for _, row := range rows {
		if have[row.OrganizationID] == nil {
			have[row.OrganizationID] = make(map[string]struct{})
		}
		have[row.OrganizationID][row.Name] = struct{}{}
	}

	var missing []systemRoleBackfill
	for _, orgID := range orgIDs {
		for _, name := range m.cfg.SystemRoles {
			if _, ok := have[orgID][name]; !ok {
				missing = append(missing, systemRoleBackfill{orgID: orgID, name: name})
			}
		}
	}
	return missing, nil
}

// ruleKey is a canonical comparison key for set diffing.
func ruleKey(r Rule) string {
	return r.Ptype + "\x00" + strings.Join(r.Values, "\x00")
}
