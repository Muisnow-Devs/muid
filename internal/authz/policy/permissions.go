package policy

// Organization-scoped permissions gating the public organization-admin
// surface. They must stay in the static configuration's catalog
// (default_policy.json).
const (
	PermissionSettingRead  = "organization/setting.read"
	PermissionSettingWrite = "organization/setting.write"
	PermissionMemberRead   = "organization/member.read"
	PermissionMemberWrite  = "organization/member.write"
	PermissionRoleRead     = "organization/role.read"
	PermissionRoleWrite    = "organization/role.write"
)
