package authzmodel

import (
	"regexp"
	"strings"

	"github.com/google/uuid"
)

// Permission strings follow "service/method.action" where service is the
// owning service namespace (e.g. "authn/oidc_client.manage"). The slash
// separator is deliberate: OIDC scopes use "service:method.action", and
// permissions must stay visually distinct from scopes.
var permissionPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*/[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$`)

// namespacePattern matches a bare service namespace (e.g. "authn").
var namespacePattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// ValidPermission reports whether permission matches the
// "service/method.action" pattern.
func ValidPermission(permission string) bool {
	return permissionPattern.MatchString(permission)
}

// ValidNamespace reports whether namespace is a bare service namespace.
func ValidNamespace(namespace string) bool {
	return namespacePattern.MatchString(namespace)
}

// SplitPermission splits "service/method.action" into the casbin object
// ("service/method") and action ("action"). It returns
// ErrInvalidPermission when the string does not match the pattern.
func SplitPermission(permission string) (obj, act string, err error) {
	if !ValidPermission(permission) {
		return "", "", ErrInvalidPermission
	}
	i := strings.LastIndexByte(permission, '.')
	return permission[:i], permission[i+1:], nil
}

// JoinPermission is the inverse of SplitPermission.
func JoinPermission(obj, act string) string {
	return obj + "." + act
}

// Namespace returns the service namespace of a permission ("authn" for
// "authn/oidc_client.manage").
func Namespace(permission string) (string, error) {
	if !ValidPermission(permission) {
		return "", ErrInvalidPermission
	}
	return permission[:strings.IndexByte(permission, '/')], nil
}

// NamespaceObjPrefix returns the casbin object prefix selecting every
// permission owned by a service namespace (e.g. "authn/").
func NamespaceObjPrefix(namespace string) string {
	return namespace + "/"
}

// UserSubject returns the casbin subject for an end user.
func UserSubject(userID uuid.UUID) string {
	return UserSubjectPrefix + userID.String()
}

// RoleSubject returns the casbin subject for an organization role.
func RoleSubject(name string) string {
	return RoleSubjectPrefix + name
}

// RoleName returns the role name of a role subject, and ok=false when the
// subject is not a role.
func RoleName(subject string) (string, bool) {
	name, ok := strings.CutPrefix(subject, RoleSubjectPrefix)
	if !ok || name == "" {
		return "", false
	}
	return name, true
}
