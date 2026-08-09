package policy

import (
	"context"
	"slices"

	"github.com/google/uuid"

	authzent "sanzi.io/muid/internal/authz/ent"
	"sanzi.io/muid/internal/authz/ent/casbinrule"
	"sanzi.io/muid/internal/authz/ent/organizationmember"
	"sanzi.io/muid/internal/authz/ent/predicate"
	"sanzi.io/muid/pkg/shared/authzmodel"
)

// defaultPageSize applies when a list request passes page_size 0.
const defaultPageSize = 100

// MemberInfo is one organization member with the role name resolved.
type MemberInfo struct {
	UserID    uuid.UUID
	Role      string
	CreatedAt int64 // unix seconds
}

// OrgMembershipInfo is one organization a user belongs to.
type OrgMembershipInfo struct {
	OrganizationID uuid.UUID
	Name           string
	Description    string
	Role           string
}

// IsMember reports organization membership from the relational source of
// truth.
func (m *Manager) IsMember(ctx context.Context, organizationID, userID uuid.UUID) (bool, error) {
	return m.db.OrganizationMember.Query().
		Where(
			organizationmember.OrganizationID(organizationID),
			organizationmember.UserID(userID),
		).
		Exist(ctx)
}

// Enforce runs the casbin decision for a "namespace/resource.action" permission
// in the organization domain.
func (m *Manager) Enforce(
	ctx context.Context,
	userID, organizationID uuid.UUID,
	permission string,
) (bool, error) {
	obj, act, err := authzmodel.SplitPermission(permission)
	if err != nil {
		return false, err
	}
	return m.enforcer.Enforce(
		authzmodel.UserSubject(userID),
		organizationID.String(),
		obj,
		act,
	)
}

// CheckPermission combines Enforce with a membership lookup (the service
// gateway response carries both).
func (m *Manager) CheckPermission(
	ctx context.Context,
	organizationID, userID uuid.UUID,
	permission string,
) (allowed, isMember bool, err error) {
	allowed, err = m.Enforce(ctx, userID, organizationID, permission)
	if err != nil {
		return false, false, err
	}
	isMember, err = m.IsMember(ctx, organizationID, userID)
	if err != nil {
		return false, false, err
	}
	return allowed, isMember, nil
}

// CheckPlatformPermission evaluates a cataloged permission against the
// isolated platform domain. An unbound user is denied without error.
func (m *Manager) CheckPlatformPermission(
	ctx context.Context,
	userID uuid.UUID,
	permission string,
) (bool, error) {
	if !authzmodel.ValidPermission(permission) ||
		permissionNamespace(permission) != authzmodel.PlatformDomain ||
		!m.cfg.HasPermission(permission) {
		return false, ErrUnknownPermission
	}
	if userID == uuid.Nil {
		return false, nil
	}
	obj, act, err := authzmodel.SplitPermission(permission)
	if err != nil {
		return false, ErrUnknownPermission
	}
	return m.enforcer.Enforce(
		authzmodel.UserSubject(userID),
		authzmodel.PlatformDomain,
		obj,
		act,
	)
}

// UserRoles returns a user's direct role names in an organization.
func (m *Manager) UserRoles(
	ctx context.Context,
	userID, organizationID uuid.UUID,
) (roles []string, isMember bool, err error) {
	member, err := m.db.OrganizationMember.Query().
		Where(
			organizationmember.OrganizationID(organizationID),
			organizationmember.UserID(userID),
		).
		WithRole().
		Only(ctx)
	if authzent.IsNotFound(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if member.Edges.Role == nil {
		return nil, true, nil
	}
	return []string{member.Edges.Role.Name}, true, nil
}

// ImplicitPermissions returns the effective permissions of a user in an
// organization: the p-rules of the user subject and every (transitively)
// inherited role, in both the organization domain and the wildcard domain.
func (m *Manager) ImplicitPermissions(
	ctx context.Context,
	userID, organizationID uuid.UUID,
) ([]string, error) {
	return m.implicitSubjectPermissions(authzmodel.UserSubject(userID), organizationID)
}

// implicitSubjectPermissions collects effective permissions for any casbin
// subject (user or role).
func (m *Manager) implicitSubjectPermissions(
	subject string,
	organizationID uuid.UUID,
) ([]string, error) {
	domain := organizationID.String()

	roles, err := m.enforcer.GetImplicitRolesForUser(subject, domain)
	if err != nil {
		return nil, err
	}
	subjects := append([]string{subject}, roles...)

	seen := make(map[string]struct{})
	var permissions []string
	for _, sub := range subjects {
		rules, err := m.enforcer.GetFilteredNamedPolicy("p", 0, sub)
		if err != nil {
			return nil, err
		}
		for _, rule := range rules {
			if len(rule) < 4 {
				continue
			}
			if rule[1] != domain && rule[1] != authzmodel.WildcardDomain {
				continue
			}
			permission := authzmodel.JoinPermission(rule[2], rule[3])
			if _, ok := seen[permission]; ok {
				continue
			}
			seen[permission] = struct{}{}
			permissions = append(permissions, permission)
		}
	}
	slices.Sort(permissions)
	return permissions, nil
}

// NamespacePolicies returns one page of the rules a service-local enforcer
// needs: p-rules whose object lives in the namespace plus the
// wildcard-domain role-hierarchy g-rules.
func (m *Manager) NamespacePolicies(
	ctx context.Context,
	namespace string,
	pageSize int,
	pageToken string,
) (rules []Rule, nextPageToken string, revision uuid.UUID, err error) {
	if !authzmodel.ValidNamespace(namespace) {
		return nil, "", uuid.Nil, ErrInvalidRule
	}
	// Platform policy is evaluated only by the central authz service. It is
	// never replicated to service-local namespace enforcers.
	if namespace == authzmodel.PlatformDomain {
		revision, err = m.Revision(ctx)
		return nil, "", revision, err
	}
	pred := casbinrule.Or(
		casbinrule.And(
			casbinrule.Ptype("p"),
			casbinrule.V1NEQ(authzmodel.PlatformDomain),
			casbinrule.V2HasPrefix(authzmodel.NamespaceObjPrefix(namespace)),
		),
		casbinrule.And(
			casbinrule.Ptype("g"),
			casbinrule.V2(authzmodel.WildcardDomain),
		),
	)
	rules, nextPageToken, err = m.pageRules(ctx, pageSize, pageToken, pred)
	if err != nil {
		return nil, "", uuid.Nil, err
	}
	revision, err = m.Revision(ctx)
	if err != nil {
		return nil, "", uuid.Nil, err
	}
	return rules, nextPageToken, revision, nil
}

// CasbinRules returns one page of raw rules, optionally filtered by ptype
// and/or domain (for p-rules the domain is v1, for g-rules v2).
func (m *Manager) CasbinRules(
	ctx context.Context,
	ptype, domain string,
	pageSize int,
	pageToken string,
) (rules []Rule, nextPageToken string, revision uuid.UUID, err error) {
	var preds []predicate.CasbinRule
	if ptype != "" {
		preds = append(preds, casbinrule.Ptype(ptype))
	}
	if domain != "" {
		preds = append(preds, casbinrule.Or(
			casbinrule.And(casbinrule.Ptype("p"), casbinrule.V1(domain)),
			casbinrule.And(casbinrule.Ptype("g"), casbinrule.V2(domain)),
		))
	}
	rules, nextPageToken, err = m.pageRules(ctx, pageSize, pageToken, preds...)
	if err != nil {
		return nil, "", uuid.Nil, err
	}
	revision, err = m.Revision(ctx)
	if err != nil {
		return nil, "", uuid.Nil, err
	}
	return rules, nextPageToken, revision, nil
}

// pageRules pages casbin_rule rows by id keyset (ids are UUIDv7, so id
// order is stable insertion order; the page token is the last row's id).
func (m *Manager) pageRules(
	ctx context.Context,
	pageSize int,
	pageToken string,
	preds ...predicate.CasbinRule,
) ([]Rule, string, error) {
	size := pageSize
	if size <= 0 {
		size = defaultPageSize
	}

	q := m.db.CasbinRule.Query().Where(preds...)
	if pageToken != "" {
		after, err := uuid.Parse(pageToken)
		if err != nil {
			return nil, "", ErrInvalidPageToken
		}
		q = q.Where(casbinrule.IDGT(after))
	}
	rows, err := q.Order(casbinrule.ByID()).Limit(size + 1).All(ctx)
	if err != nil {
		return nil, "", err
	}

	next := ""
	if len(rows) > size {
		rows = rows[:size]
		next = rows[len(rows)-1].ID.String()
	}
	rules := make([]Rule, 0, len(rows))
	for _, row := range rows {
		rules = append(rules, ruleFromRow(row))
	}
	return rules, next, nil
}

// Members returns one page of an organization's members with role names.
func (m *Manager) Members(
	ctx context.Context,
	organizationID uuid.UUID,
	pageSize int,
	pageToken string,
) ([]MemberInfo, string, error) {
	size := pageSize
	if size <= 0 {
		size = defaultPageSize
	}

	q := m.db.OrganizationMember.Query().
		Where(organizationmember.OrganizationID(organizationID))
	if pageToken != "" {
		after, err := uuid.Parse(pageToken)
		if err != nil {
			return nil, "", ErrInvalidPageToken
		}
		q = q.Where(organizationmember.IDGT(after))
	}
	rows, err := q.
		WithRole().
		Order(organizationmember.ByID()).
		Limit(size + 1).
		All(ctx)
	if err != nil {
		return nil, "", err
	}

	next := ""
	if len(rows) > size {
		rows = rows[:size]
		next = rows[len(rows)-1].ID.String()
	}
	members := make([]MemberInfo, 0, len(rows))
	for _, row := range rows {
		info := MemberInfo{
			UserID:    row.UserID,
			CreatedAt: row.CreatedAt.Unix(),
		}
		if row.Edges.Role != nil {
			info.Role = row.Edges.Role.Name
		}
		members = append(members, info)
	}
	return members, next, nil
}

// UserOrganizations returns one page of the organizations a user belongs
// to, with the user's role name in each.
func (m *Manager) UserOrganizations(
	ctx context.Context,
	userID uuid.UUID,
	pageSize int,
	pageToken string,
) ([]OrgMembershipInfo, string, error) {
	size := pageSize
	if size <= 0 {
		size = defaultPageSize
	}

	q := m.db.OrganizationMember.Query().
		Where(organizationmember.UserID(userID))
	if pageToken != "" {
		after, err := uuid.Parse(pageToken)
		if err != nil {
			return nil, "", ErrInvalidPageToken
		}
		q = q.Where(organizationmember.IDGT(after))
	}
	rows, err := q.
		WithOrganization().
		WithRole().
		Order(organizationmember.ByID()).
		Limit(size + 1).
		All(ctx)
	if err != nil {
		return nil, "", err
	}

	next := ""
	if len(rows) > size {
		rows = rows[:size]
		next = rows[len(rows)-1].ID.String()
	}
	memberships := make([]OrgMembershipInfo, 0, len(rows))
	for _, row := range rows {
		info := OrgMembershipInfo{}
		if row.Edges.Organization != nil {
			info.OrganizationID = row.Edges.Organization.ID
			info.Name = row.Edges.Organization.Name
			info.Description = row.Edges.Organization.Description
		}
		if row.Edges.Role != nil {
			info.Role = row.Edges.Role.Name
		}
		memberships = append(memberships, info)
	}
	return memberships, next, nil
}
