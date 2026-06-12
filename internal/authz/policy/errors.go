package policy

import "errors"

var (
	// ErrInvalidRule reports a casbin rule with an unsupported shape (bad
	// ptype, too many columns, or values violating the model conventions).
	ErrInvalidRule = errors.New("invalid casbin rule")

	// ErrInvalidConfig reports a static policy configuration that fails
	// validation (unknown grants, malformed names, broken hierarchy).
	ErrInvalidConfig = errors.New("invalid policy configuration")

	// ErrOrganizationNotFound reports an unknown organization id.
	ErrOrganizationNotFound = errors.New("organization not found")

	// ErrRoleNotFound reports an unknown role name in the organization.
	ErrRoleNotFound = errors.New("role not found")

	// ErrRoleExists reports a role-name collision in the organization.
	ErrRoleExists = errors.New("role already exists")

	// ErrSystemRoleImmutable reports an attempt to rename, regrant, or
	// delete a system role.
	ErrSystemRoleImmutable = errors.New("system role is immutable")

	// ErrRoleInUse reports an attempt to delete a role still assigned to
	// members.
	ErrRoleInUse = errors.New("role is assigned to members")

	// ErrLastOwner reports an attempt to remove or demote the last owner of
	// an organization.
	ErrLastOwner = errors.New("organization must keep at least one owner")

	// ErrUnknownPermission reports a permission string outside the static
	// configuration's catalog.
	ErrUnknownPermission = errors.New("unknown permission")

	// ErrAlreadyMember reports an AddMember for an existing member.
	ErrAlreadyMember = errors.New("user is already a member")

	// ErrNotMember reports a member operation for a non-member.
	ErrNotMember = errors.New("user is not a member")

	// ErrPermissionDenied reports a caller lacking the permission an
	// organization-admin operation requires.
	ErrPermissionDenied = errors.New("permission denied")

	// ErrInvalidPageToken reports a malformed list page token.
	ErrInvalidPageToken = errors.New("invalid page token")

	// ErrOrganizationExists reports an organization name/domain collision.
	ErrOrganizationExists = errors.New("organization already exists")
)
