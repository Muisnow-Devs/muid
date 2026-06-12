package policy

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"

	"sanzi.io/muid/pkg/shared/authzmodel"
)

// roleNamePattern matches organization role names (mirrors the buf.validate
// pattern on the role fields in authz protos).
var roleNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{1,63}$`)

// validRoleName reports whether name is an acceptable role name.
func validRoleName(name string) bool {
	return roleNamePattern.MatchString(name)
}

// RoleOwner is the system role with full control of an organization. The
// static configuration must define it; the Manager's guard rails (last-owner
// protection, owner grant/revoke restrictions) key off this name.
const RoleOwner = "owner"

//go:embed default_policy.json
var defaultPolicyJSON []byte

// StaticConfig declares the permission catalog and the wildcard-domain rules
// (system roles, role hierarchy, default grants) that the reconciler keeps
// in sync with casbin_rule at startup and on ReloadPolicyConfig.
type StaticConfig struct {
	// Permissions is the catalog: service namespace -> "method.action"
	// entries (e.g. "authn" -> ["oidc_client.manage"]). Every grant —
	// static or custom role — must reference a cataloged permission.
	Permissions map[string][]string `json:"permissions"`
	// SystemRoles are seeded as OrganizationRole rows for every
	// organization and may not be modified per organization.
	SystemRoles []string `json:"system_roles"`
	// RoleInheritance lists [parent, child] pairs: the parent role inherits
	// every grant of the child role (e.g. ["owner", "admin"]).
	RoleInheritance [][]string `json:"role_inheritance"`
	// Grants assigns cataloged permissions to system roles. Grants are
	// deltas: inheritance supplies the rest.
	Grants map[string][]string `json:"grants"`
}

// LoadStaticConfig resolves the static configuration: a file path wins over
// inline JSON, which wins over the embedded default. The result is
// validated.
func LoadStaticConfig(path, inlineJSON string) (StaticConfig, error) {
	raw := defaultPolicyJSON
	switch {
	case path != "":
		data, err := os.ReadFile(path)
		if err != nil {
			return StaticConfig{}, errors.Join(ErrInvalidConfig, err)
		}
		raw = data
	case inlineJSON != "":
		raw = []byte(inlineJSON)
	}

	var cfg StaticConfig
	err := json.Unmarshal(raw, &cfg)
	if err != nil {
		return StaticConfig{}, errors.Join(ErrInvalidConfig, err)
	}
	err = cfg.Validate()
	if err != nil {
		return StaticConfig{}, err
	}
	return cfg, nil
}

// Validate checks internal consistency; all reported problems wrap
// ErrInvalidConfig.
func (c StaticConfig) Validate() error {
	if len(c.SystemRoles) == 0 {
		return fmt.Errorf("%w: system_roles is empty", ErrInvalidConfig)
	}
	if !slices.Contains(c.SystemRoles, RoleOwner) {
		return fmt.Errorf("%w: system_roles must include %q", ErrInvalidConfig, RoleOwner)
	}
	for _, role := range c.SystemRoles {
		if !validRoleName(role) {
			return fmt.Errorf("%w: bad system role name %q", ErrInvalidConfig, role)
		}
	}

	catalog := c.Catalog()
	for ns, entries := range c.Permissions {
		for _, entry := range entries {
			if !authzmodel.ValidPermission(ns + "/" + entry) {
				return fmt.Errorf(
					"%w: bad permission %q in namespace %q",
					ErrInvalidConfig,
					entry,
					ns,
				)
			}
		}
	}

	for _, pair := range c.RoleInheritance {
		if len(pair) != 2 {
			return fmt.Errorf(
				"%w: role_inheritance entries must be [parent, child] pairs, got %v",
				ErrInvalidConfig,
				pair,
			)
		}
		for _, role := range pair {
			if !slices.Contains(c.SystemRoles, role) {
				return fmt.Errorf(
					"%w: role_inheritance references unknown system role %q",
					ErrInvalidConfig,
					role,
				)
			}
		}
	}

	for role, permissions := range c.Grants {
		if !slices.Contains(c.SystemRoles, role) {
			return fmt.Errorf("%w: grants reference unknown system role %q", ErrInvalidConfig, role)
		}
		for _, permission := range permissions {
			if _, ok := catalog[permission]; !ok {
				return fmt.Errorf(
					"%w: grant %q for role %q is not in the catalog",
					ErrInvalidConfig,
					permission,
					role,
				)
			}
		}
	}
	return nil
}

// Catalog returns the set of full permission strings
// ("service/method.action") declared by the configuration.
func (c StaticConfig) Catalog() map[string]struct{} {
	out := make(map[string]struct{})
	for ns, entries := range c.Permissions {
		for _, entry := range entries {
			out[ns+"/"+entry] = struct{}{}
		}
	}
	return out
}

// HasPermission reports whether the permission is in the catalog.
func (c StaticConfig) HasPermission(permission string) bool {
	_, ok := c.Catalog()[permission]
	return ok
}

// WildcardRules returns the desired wildcard-domain casbin rules: role
// hierarchy g-rules and system-role grant p-rules. The set is what the
// reconciler diffs against storage.
func (c StaticConfig) WildcardRules() ([]Rule, error) {
	var rules []Rule
	for _, pair := range c.RoleInheritance {
		rules = append(rules, Rule{
			Ptype: "g",
			Values: []string{
				authzmodel.RoleSubject(pair[0]),
				authzmodel.RoleSubject(pair[1]),
				authzmodel.WildcardDomain,
			},
		})
	}
	for _, role := range c.SystemRoles {
		for _, permission := range c.Grants[role] {
			obj, act, err := authzmodel.SplitPermission(permission)
			if err != nil {
				return nil, errors.Join(ErrInvalidConfig, err)
			}
			rules = append(rules, Rule{
				Ptype:  "p",
				Values: []string{authzmodel.RoleSubject(role), authzmodel.WildcardDomain, obj, act},
			})
		}
	}
	return rules, nil
}
