package audit

// Action constants form the stable audit vocabulary, written verbatim to the
// action column. Format is "<resource>.<verb>". Treat these as an append-only
// contract: rename nothing, since downstream queries and dashboards key off
// the literal strings.
const (
	// authz — organizations, roles, memberships, raw casbin rules.
	ActionOrganizationCreate = "organization.create"
	ActionOrganizationDelete = "organization.delete"
	ActionRoleCreate         = "role.create"
	ActionRoleUpdate         = "role.update"
	ActionRoleDelete         = "role.delete"
	ActionMemberAdd          = "member.add"
	ActionMemberRemove       = "member.remove"
	ActionMemberRoleChange   = "member.role_change"
	ActionRulesAdd           = "rules.add"
	ActionRulesRemove        = "rules.remove"

	// profile — user and organization profiles, avatars.
	ActionProfileCreate             = "profile.create"
	ActionProfileUpdate             = "profile.update"
	ActionProfileAvatarUpdate       = "profile.avatar.update"
	ActionOrganizationProfileCreate = "organization_profile.create"
	ActionOrganizationProfileUpdate = "organization_profile.update"

	// authn — OIDC client administration.
	ActionOIDCClientCreate      = "oidc_client.create"
	ActionOIDCClientUpdate      = "oidc_client.update"
	ActionOIDCRedirectURIAdd    = "oidc_client.redirect_uri.add"
	ActionOIDCRedirectURIRemove = "oidc_client.redirect_uri.remove"
	ActionOIDCSecretCreate      = "oidc_client.secret.create"
	ActionOIDCSecretRevoke      = "oidc_client.secret.revoke"
	ActionOIDCAccessGrantAdd    = "oidc_client.access_grant.add"
	ActionOIDCAccessGrantRemove = "oidc_client.access_grant.remove"

	// authn — sessions, identities, consent, tokens.
	ActionSessionCreate           = "session.create"
	ActionSessionRevoke           = "session.revoke"
	ActionIdentityLink            = "identity.link"
	ActionFederatedIdentityRevoke = "federated_identity.revoke"
	ActionConsentRevoke           = "consent.revoke"
	ActionTokenRevoke             = "token.revoke"
)

// Resource type constants name the entity an audit entry is about, written to
// the resource_type column.
const (
	ResourceOrganization        = "organization"
	ResourceRole                = "role"
	ResourceMember              = "member"
	ResourceCasbinRules         = "casbin_rules"
	ResourceProfile             = "profile"
	ResourceAvatar              = "avatar"
	ResourceOrganizationProfile = "organization_profile"
	ResourceOIDCClient          = "oidc_client"
	ResourceSession             = "session"
	ResourceIdentity            = "identity"
	ResourceFederatedIdentity   = "federated_identity"
	ResourceConsent             = "consent"
	ResourceToken               = "token"
)
