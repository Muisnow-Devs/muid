package policy

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"

	authzevent "sanzi.io/muid/api/proto/event/v1/authz"
	authzent "sanzi.io/muid/internal/authz/ent"
	"sanzi.io/muid/internal/authz/ent/casbinrule"
	"sanzi.io/muid/internal/authz/ent/organizationrole"
	"sanzi.io/muid/internal/authz/ent/policyrevision"
	"sanzi.io/muid/internal/authz/ent/predicate"
	"sanzi.io/muid/pkg/enttx"
	"sanzi.io/muid/pkg/shared/authzmodel"
)

// Reconcile brings static wildcard and platform-domain casbin rules in line
// with the static configuration (insert missing, delete stale) and backfills
// missing system OrganizationRole rows for existing organizations. It is
// idempotent and runs at startup and on ReloadPolicyConfig; reloading uses the
// Manager's already validated configuration source rather than rereading it.
func (m *Manager) Reconcile(ctx context.Context) (changed bool, revision uuid.UUID, err error) {
	m.reconcileMu.Lock()
	defer m.reconcileMu.Unlock()
	reconcileDatabaseMu.Lock()
	defer reconcileDatabaseMu.Unlock()

	desired, err := m.cfg.StaticRules()
	if err != nil {
		return false, uuid.Nil, err
	}
	desiredKeys := make(map[string]Rule, len(desired))
	for _, r := range desired {
		desiredKeys[ruleKey(r)] = r
	}

	err = m.ensurePolicyRevision(ctx)
	if err != nil {
		return false, uuid.Nil, err
	}

	revision, err = enttx.Run(ctx, m.db.Tx,
		func(ctx context.Context, tx *authzent.Tx) (uuid.UUID, error) {
			// Updating this singleton row obtains a PostgreSQL transaction row
			// lock, serializing the read/diff/write sequence across replicas.
			err := tx.PolicyRevision.UpdateOneID(policyRevisionRowID).
				SetUpdatedAt(time.Now()).
				Exec(ctx)
			if err != nil {
				return uuid.Nil, err
			}
			actualRows, err := tx.CasbinRule.Query().Where(staticRulePredicate()).All(ctx)
			if err != nil {
				return uuid.Nil, err
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
			missingRoles, err := m.missingSystemRolesFrom(ctx, tx.Client())
			if err != nil {
				return uuid.Nil, err
			}
			rulesChanged := len(toInsert) > 0 || len(toDelete) > 0
			changed = rulesChanged
			if !rulesChanged && len(missingRoles) == 0 {
				return revisionFromClient(ctx, tx.Client())
			}
			err = insertRules(ctx, tx.CasbinRule, toInsert)
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
				return revisionFromClient(ctx, tx.Client())
			}
			return bumpRevision(ctx, tx)
		})
	if err != nil {
		return false, uuid.Nil, err
	}

	if changed {
		err = m.enforcer.LoadPolicy()
		if err != nil {
			return true, revision, err
		}
		m.publishChange(ctx, policyChange{
			kind:     authzevent.PolicyChangeKind_POLICY_CHANGE_KIND_CONFIG_RELOADED,
			revision: revision,
		})
	}
	return changed, revision, nil
}

func staticRulePredicate() predicate.CasbinRule {
	return casbinrule.Or(
		casbinrule.And(casbinrule.Ptype("p"), casbinrule.V1In(authzmodel.WildcardDomain, authzmodel.PlatformDomain)),
		casbinrule.And(casbinrule.Ptype("g"), casbinrule.V2In(authzmodel.WildcardDomain, authzmodel.PlatformDomain)),
	)
}

func (m *Manager) ensurePolicyRevision(ctx context.Context) error {
	err := m.db.PolicyRevision.Create().SetID(policyRevisionRowID).SetRevision(uuid.Nil).Exec(ctx)
	if authzent.IsConstraintError(err) {
		return nil
	}
	return err
}

func revisionFromClient(ctx context.Context, client *authzent.Client) (uuid.UUID, error) {
	row, err := client.PolicyRevision.Query().Where(policyrevision.ID(policyRevisionRowID)).Only(ctx)
	if authzent.IsNotFound(err) {
		return uuid.Nil, nil
	}
	if err != nil {
		return uuid.Nil, err
	}
	return row.Revision, nil
}

// systemRoleBackfill is one missing (organization, system role) pair.
type systemRoleBackfill struct {
	orgID uuid.UUID
	name  string
}

// missingSystemRoles finds organizations lacking a system role row.
func (m *Manager) missingSystemRoles(ctx context.Context) ([]systemRoleBackfill, error) {
	return m.missingSystemRolesFrom(ctx, m.db)
}

func (m *Manager) missingSystemRolesFrom(ctx context.Context, client *authzent.Client) ([]systemRoleBackfill, error) {
	orgIDs, err := client.Organization.Query().IDs(ctx)
	if err != nil {
		return nil, err
	}
	if len(orgIDs) == 0 {
		return nil, nil
	}

	rows, err := client.OrganizationRole.Query().
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
