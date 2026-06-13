package policy

import (
	"context"
	"slices"

	"github.com/google/uuid"

	authzevent "sanzi.io/muid/api/proto/event/v1/authz"
	authzent "sanzi.io/muid/internal/authz/ent"
	"sanzi.io/muid/internal/authz/ent/casbinrule"
	"sanzi.io/muid/internal/authz/ent/organization"
	"sanzi.io/muid/internal/authz/ent/organizationmember"
	"sanzi.io/muid/internal/authz/ent/organizationrole"
	"sanzi.io/muid/pkg/audit"
	"sanzi.io/muid/pkg/enttx"
	"sanzi.io/muid/pkg/log"
	"sanzi.io/muid/pkg/shared/authzmodel"
)

// RoleInfo is one organization role with its effective permissions
// (inheritance expanded; for system roles these come from the
// wildcard-domain rules).
type RoleInfo struct {
	ID          uuid.UUID
	Name        string
	Description string
	IsSystem    bool
	Permissions []string
}

// CreateRole creates a custom role with the given cataloged permissions.
func (m *Manager) CreateRole(
	ctx context.Context,
	organizationID uuid.UUID,
	name, description string,
	permissions []string,
) (RoleInfo, error) {
	if !validRoleName(name) {
		return RoleInfo{}, ErrInvalidRule
	}
	if slices.Contains(m.cfg.SystemRoles, name) {
		return RoleInfo{}, ErrRoleExists
	}
	permissions = normalizePermissions(permissions)
	err := m.validateCataloged(permissions)
	if err != nil {
		return RoleInfo{}, err
	}
	err = m.requireOrganization(ctx, organizationID)
	if err != nil {
		return RoleInfo{}, err
	}

	domain := organizationID.String()
	grantRules := grantRulesFor(name, domain, permissions)

	type txOut struct {
		roleID   uuid.UUID
		revision uuid.UUID
	}
	out, err := enttx.Run(ctx, m.db.Tx,
		func(ctx context.Context, tx *authzent.Tx) (txOut, error) {
			role, err := tx.OrganizationRole.Create().
				SetOrganizationID(organizationID).
				SetName(name).
				SetDescription(description).
				Save(ctx)
			if authzent.IsConstraintError(err) {
				return txOut{}, ErrRoleExists
			}
			if err != nil {
				return txOut{}, err
			}
			err = insertRules(ctx, tx.CasbinRule, grantRules)
			if err != nil {
				return txOut{}, err
			}
			err = writeAudit(ctx, tx, audit.Entry{
				Action:         audit.ActionRoleCreate,
				ResourceType:   audit.ResourceRole,
				ResourceID:     role.ID.String(),
				OrganizationID: &organizationID,
				Changes: audit.Changes(nil, map[string]any{
					"name":        name,
					"description": description,
					"permissions": permissions,
				}),
			})
			if err != nil {
				return txOut{}, err
			}
			rev, err := bumpRevision(ctx, tx)
			if err != nil {
				return txOut{}, err
			}
			return txOut{roleID: role.ID, revision: rev}, nil
		})
	if err != nil {
		return RoleInfo{}, err
	}

	m.memoryAddRules(ctx, grantRules)
	m.publishChange(ctx, policyChange{
		kind:       authzevent.PolicyChangeKind_POLICY_CHANGE_KIND_ROLE_GRANTS_CHANGED,
		orgID:      organizationID,
		namespaces: namespacesOf(permissions),
		role:       name,
		revision:   out.revision,
	})

	return RoleInfo{
		ID:          out.roleID,
		Name:        name,
		Description: description,
		Permissions: permissions,
	}, nil
}

// UpdateRole renames a custom role and/or replaces its grants. System roles
// are immutable.
func (m *Manager) UpdateRole(
	ctx context.Context,
	organizationID uuid.UUID,
	name, newName, description string,
	permissions []string,
) (RoleInfo, error) {
	finalName := name
	if newName != "" && newName != name {
		if !validRoleName(newName) || slices.Contains(m.cfg.SystemRoles, newName) {
			return RoleInfo{}, ErrInvalidRule
		}
		finalName = newName
	}
	permissions = normalizePermissions(permissions)
	err := m.validateCataloged(permissions)
	if err != nil {
		return RoleInfo{}, err
	}

	role, err := m.roleByName(ctx, organizationID, name)
	if err != nil {
		return RoleInfo{}, err
	}
	if role.IsSystem {
		return RoleInfo{}, ErrSystemRoleImmutable
	}

	domain := organizationID.String()
	oldSubject := authzmodel.RoleSubject(name)
	grantRules := grantRulesFor(finalName, domain, permissions)

	type txOut struct {
		oldNamespaces []string
		revision      uuid.UUID
	}
	out, err := enttx.Run(ctx, m.db.Tx,
		func(ctx context.Context, tx *authzent.Tx) (txOut, error) {
			update := tx.OrganizationRole.UpdateOneID(role.ID).SetDescription(description)
			if finalName != name {
				update = update.SetName(finalName)
			}
			err := update.Exec(ctx)
			if authzent.IsConstraintError(err) {
				return txOut{}, ErrRoleExists
			}
			if err != nil {
				return txOut{}, err
			}

			oldRows, err := tx.CasbinRule.Query().
				Where(
					casbinrule.Ptype("p"),
					casbinrule.V0(oldSubject),
					casbinrule.V1(domain),
				).
				All(ctx)
			if err != nil {
				return txOut{}, err
			}
			oldNamespaces := namespacesOfRules(oldRows)

			_, err = tx.CasbinRule.Delete().
				Where(
					casbinrule.Ptype("p"),
					casbinrule.V0(oldSubject),
					casbinrule.V1(domain),
				).
				Exec(ctx)
			if err != nil {
				return txOut{}, err
			}
			err = insertRules(ctx, tx.CasbinRule, grantRules)
			if err != nil {
				return txOut{}, err
			}

			if finalName != name {
				// Memberships reference the role subject in g-rules.
				_, err = tx.CasbinRule.Update().
					Where(
						casbinrule.Ptype("g"),
						casbinrule.V1(oldSubject),
						casbinrule.V2(domain),
					).
					SetV1(authzmodel.RoleSubject(finalName)).
					Save(ctx)
				if err != nil {
					return txOut{}, err
				}
			}

			err = writeAudit(ctx, tx, audit.Entry{
				Action:         audit.ActionRoleUpdate,
				ResourceType:   audit.ResourceRole,
				ResourceID:     role.ID.String(),
				OrganizationID: &organizationID,
				Changes: audit.Changes(
					map[string]any{"name": name},
					map[string]any{
						"name":        finalName,
						"description": description,
						"permissions": permissions,
					},
				),
			})
			if err != nil {
				return txOut{}, err
			}

			rev, err := bumpRevision(ctx, tx)
			if err != nil {
				return txOut{}, err
			}
			return txOut{oldNamespaces: oldNamespaces, revision: rev}, nil
		})
	if err != nil {
		return RoleInfo{}, err
	}

	// Renames rewrite g-rules; reload instead of computing the delta.
	err = m.enforcer.LoadPolicy()
	if err != nil {
		log.LogUnexpected(ctx, "authz enforcer reload after role update", err.Error())
	}
	m.publishChange(ctx, policyChange{
		kind:       authzevent.PolicyChangeKind_POLICY_CHANGE_KIND_ROLE_GRANTS_CHANGED,
		orgID:      organizationID,
		namespaces: unionNamespaces(out.oldNamespaces, namespacesOf(permissions)),
		role:       finalName,
		revision:   out.revision,
	})

	return RoleInfo{
		ID:          role.ID,
		Name:        finalName,
		Description: description,
		Permissions: permissions,
	}, nil
}

// DeleteRole removes an unassigned custom role and its grants.
func (m *Manager) DeleteRole(ctx context.Context, organizationID uuid.UUID, name string) error {
	role, err := m.roleByName(ctx, organizationID, name)
	if err != nil {
		return err
	}
	if role.IsSystem {
		return ErrSystemRoleImmutable
	}

	assigned, err := m.db.OrganizationMember.Query().
		Where(organizationmember.RoleID(role.ID)).
		Exist(ctx)
	if err != nil {
		return err
	}
	if assigned {
		return ErrRoleInUse
	}

	domain := organizationID.String()
	subject := authzmodel.RoleSubject(name)

	type txOut struct {
		namespaces []string
		revision   uuid.UUID
	}
	out, err := enttx.Run(ctx, m.db.Tx,
		func(ctx context.Context, tx *authzent.Tx) (txOut, error) {
			oldRows, err := tx.CasbinRule.Query().
				Where(
					casbinrule.Ptype("p"),
					casbinrule.V0(subject),
					casbinrule.V1(domain),
				).
				All(ctx)
			if err != nil {
				return txOut{}, err
			}

			_, err = tx.CasbinRule.Delete().
				Where(casbinrule.Or(
					casbinrule.And(
						casbinrule.Ptype("p"),
						casbinrule.V0(subject),
						casbinrule.V1(domain),
					),
					casbinrule.And(
						casbinrule.Ptype("g"),
						casbinrule.V1(subject),
						casbinrule.V2(domain),
					),
				)).
				Exec(ctx)
			if err != nil {
				return txOut{}, err
			}
			err = tx.OrganizationRole.DeleteOneID(role.ID).Exec(ctx)
			if err != nil {
				return txOut{}, err
			}
			err = writeAudit(ctx, tx, audit.Entry{
				Action:         audit.ActionRoleDelete,
				ResourceType:   audit.ResourceRole,
				ResourceID:     role.ID.String(),
				OrganizationID: &organizationID,
				Changes:        audit.Changes(map[string]any{"name": name}, nil),
			})
			if err != nil {
				return txOut{}, err
			}
			rev, err := bumpRevision(ctx, tx)
			if err != nil {
				return txOut{}, err
			}
			return txOut{namespaces: namespacesOfRules(oldRows), revision: rev}, nil
		})
	if err != nil {
		return err
	}

	_, err = m.enforcer.RemoveFilteredPolicy(0, subject, domain)
	if err != nil {
		log.LogUnexpected(ctx, "authz enforcer delta after role delete", err.Error())
	}
	m.publishChange(ctx, policyChange{
		kind:       authzevent.PolicyChangeKind_POLICY_CHANGE_KIND_ROLE_DELETED,
		orgID:      organizationID,
		namespaces: out.namespaces,
		role:       name,
		revision:   out.revision,
	})
	return nil
}

// Roles lists an organization's roles with effective permissions.
func (m *Manager) Roles(ctx context.Context, organizationID uuid.UUID) ([]RoleInfo, error) {
	err := m.requireOrganization(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	rows, err := m.db.OrganizationRole.Query().
		Where(organizationrole.OrganizationID(organizationID)).
		Order(organizationrole.ByName()).
		All(ctx)
	if err != nil {
		return nil, err
	}

	roles := make([]RoleInfo, 0, len(rows))
	for _, row := range rows {
		permissions, err := m.implicitSubjectPermissions(
			authzmodel.RoleSubject(row.Name),
			organizationID,
		)
		if err != nil {
			return nil, err
		}
		roles = append(roles, RoleInfo{
			ID:          row.ID,
			Name:        row.Name,
			Description: row.Description,
			IsSystem:    row.IsSystem,
			Permissions: permissions,
		})
	}
	return roles, nil
}

// roleByName loads one role row, mapping not-found to sentinels.
func (m *Manager) roleByName(
	ctx context.Context,
	organizationID uuid.UUID,
	name string,
) (*authzent.OrganizationRole, error) {
	role, err := m.db.OrganizationRole.Query().
		Where(
			organizationrole.OrganizationID(organizationID),
			organizationrole.Name(name),
		).
		Only(ctx)
	if authzent.IsNotFound(err) {
		return nil, ErrRoleNotFound
	}
	if err != nil {
		return nil, err
	}
	return role, nil
}

// requireOrganization maps a missing organization to its sentinel.
func (m *Manager) requireOrganization(ctx context.Context, organizationID uuid.UUID) error {
	exists, err := m.db.Organization.Query().
		Where(organization.ID(organizationID)).
		Exist(ctx)
	if err != nil {
		return err
	}
	if !exists {
		return ErrOrganizationNotFound
	}
	return nil
}

// validateCataloged rejects permissions outside the static catalog.
func (m *Manager) validateCataloged(permissions []string) error {
	catalog := m.cfg.Catalog()
	for _, permission := range permissions {
		if _, ok := catalog[permission]; !ok {
			return ErrUnknownPermission
		}
	}
	return nil
}

// memoryAddRules applies committed rules to the in-memory enforcer. Errors
// are logged only: storage already committed and the periodic reload heals
// drift.
func (m *Manager) memoryAddRules(ctx context.Context, rules []Rule) {
	for _, r := range rules {
		var err error
		switch r.Ptype {
		case "p":
			_, err = m.enforcer.AddPolicy(toAnySlice(r.Values)...)
		case "g":
			_, err = m.enforcer.AddGroupingPolicy(toAnySlice(r.Values)...)
		}
		if err != nil {
			log.LogUnexpected(ctx, "authz enforcer delta add", err.Error())
		}
	}
}

// memoryRemoveRules removes committed rule deletions from the in-memory
// enforcer (same error policy as memoryAddRules).
func (m *Manager) memoryRemoveRules(ctx context.Context, rules []Rule) {
	for _, r := range rules {
		var err error
		switch r.Ptype {
		case "p":
			_, err = m.enforcer.RemovePolicy(toAnySlice(r.Values)...)
		case "g":
			_, err = m.enforcer.RemoveGroupingPolicy(toAnySlice(r.Values)...)
		}
		if err != nil {
			log.LogUnexpected(ctx, "authz enforcer delta remove", err.Error())
		}
	}
}

func toAnySlice(values []string) []any {
	out := make([]any, len(values))
	for i, v := range values {
		out[i] = v
	}
	return out
}

// grantRulesFor builds the p-rules granting permissions to a role in one
// organization domain.
func grantRulesFor(roleName, domain string, permissions []string) []Rule {
	rules := make([]Rule, 0, len(permissions))
	for _, permission := range permissions {
		// Permissions are validated against the catalog first, so
		// SplitPermission cannot fail here.
		obj, act, err := authzmodel.SplitPermission(permission)
		if err != nil {
			continue
		}
		rules = append(rules, Rule{
			Ptype:  "p",
			Values: []string{authzmodel.RoleSubject(roleName), domain, obj, act},
		})
	}
	return rules
}

// normalizePermissions sorts and dedupes a permission list.
func normalizePermissions(permissions []string) []string {
	out := slices.Clone(permissions)
	slices.Sort(out)
	return slices.Compact(out)
}

// namespacesOf returns the sorted distinct namespaces of permissions.
func namespacesOf(permissions []string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, permission := range permissions {
		ns, err := authzmodel.Namespace(permission)
		if err != nil {
			continue
		}
		if _, ok := seen[ns]; ok {
			continue
		}
		seen[ns] = struct{}{}
		out = append(out, ns)
	}
	slices.Sort(out)
	return out
}

// namespacesOfRules extracts namespaces from stored p-rule objects.
func namespacesOfRules(rows []*authzent.CasbinRule) []string {
	permissions := make([]string, 0, len(rows))
	for _, row := range rows {
		permissions = append(permissions, authzmodel.JoinPermission(row.V2, row.V3))
	}
	return namespacesOf(permissions)
}

// unionNamespaces merges two sorted namespace lists.
func unionNamespaces(a, b []string) []string {
	out := append(slices.Clone(a), b...)
	slices.Sort(out)
	return slices.Compact(out)
}
