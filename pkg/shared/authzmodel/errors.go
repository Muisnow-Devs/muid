package authzmodel

import "errors"

var (
	// ErrInvalidPermission reports a permission string that does not match
	// the "service/method.action" pattern.
	ErrInvalidPermission = errors.New("invalid permission string")

	// ErrRoleManagerInit reports that the casbin role manager could not be
	// configured for wildcard-domain matching.
	ErrRoleManagerInit = errors.New("casbin role manager init failed")
)
