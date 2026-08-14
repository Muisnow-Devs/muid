// Package authzmodel holds the casbin model and the permission-string
// helpers shared by the authz service and the per-service local enforcers
// (pkg/authzclient). Keeping both sides on the same model guarantees that a
// rule replicated out of authz evaluates identically everywhere.
package authzmodel

import (
	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/util"
)

// Model is the shared casbin model: organization-scoped RBAC where the
// domain is the organization UUID. Rules seeded from the static policy
// configuration (system roles, role hierarchy) use the wildcard domain "*"
// so a single rule applies to every organization; the matcher and the
// role-manager domain matching configured by NewSyncedEnforcer make the
// wildcard effective for both p- and g-rules.
const Model = `[request_definition]
r = sub, dom, obj, act

[policy_definition]
p = sub, dom, obj, act

[role_definition]
g = _, _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub, r.dom) && (p.dom == r.dom || (p.dom == "*" && r.dom != "platform")) && p.obj == r.obj && p.act == r.act
`

const (
	// UserSubjectPrefix marks casbin subjects that are end users.
	UserSubjectPrefix = "user:"
	// RoleSubjectPrefix marks casbin subjects that are organization roles.
	RoleSubjectPrefix = "role:"
	// WildcardDomain is the domain used by rules that apply to every
	// organization (system-role grants and the role hierarchy).
	WildcardDomain = "*"
	// PlatformDomain isolates platform-administration rules from organization
	// rules, including wildcard system-role grants.
	PlatformDomain = "platform"

	PlatformPermissionOrganizationWrite = "platform/organization.write"
	PlatformPermissionPolicyRead        = "platform/policy.read"
	PlatformPermissionPolicyWrite       = "platform/policy.write"
	PlatformPermissionPolicyReload      = "platform/policy.reload"
	PlatformPermissionOIDCClientRead    = "platform/oidc_client.read"
	PlatformPermissionOIDCClientWrite   = "platform/oidc_client.write"
)

// NewSyncedEnforcer returns a synced enforcer on the shared model with
// wildcard-domain role matching configured and no adapter attached. Callers
// attach persistence (SetAdapter + LoadPolicy) or feed rules through the
// policy-management APIs.
func NewSyncedEnforcer() (*casbin.SyncedEnforcer, error) {
	m, err := model.NewModelFromString(Model)
	if err != nil {
		return nil, err
	}
	e, err := casbin.NewSyncedEnforcer(m)
	if err != nil {
		return nil, err
	}
	if !e.AddNamedDomainMatchingFunc("g", "keyMatch", util.KeyMatch) {
		return nil, ErrRoleManagerInit
	}
	return e, nil
}
