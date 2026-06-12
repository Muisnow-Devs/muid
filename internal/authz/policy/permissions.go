package policy

// Authz's own permissions ("authz" namespace) gating the public
// organization-admin surface. They must stay in the static configuration's
// catalog (default_policy.json).
const (
	PermissionOrgView      = "authz/org.view"
	PermissionOrgManage    = "authz/org.manage"
	PermissionMemberView   = "authz/member.view"
	PermissionMemberManage = "authz/member.manage"
	PermissionRoleView     = "authz/role.view"
	PermissionRoleManage   = "authz/role.manage"
)
