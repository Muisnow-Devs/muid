package authzmodel

import (
	"testing"
)

// TestWildcardDomainRules verifies the load-bearing model property: rules
// stored with the wildcard domain "*" (system-role grants and the role
// hierarchy) apply inside every concrete organization domain, while
// per-organization rules stay scoped to their organization.
func TestWildcardDomainRules(t *testing.T) {
	t.Parallel()

	const (
		org1 = "0195a000-0000-7000-8000-0000000000a1"
		org2 = "0195a000-0000-7000-8000-0000000000a2"
	)

	e, err := NewSyncedEnforcer()
	if err != nil {
		t.Fatalf("NewSyncedEnforcer() error = %v", err)
	}

	rules := [][]string{
		// Wildcard system grants.
		{"role:member", WildcardDomain, "authz/org", "view"},
		{"role:admin", WildcardDomain, "authn/oidc_client", "manage"},
		// Per-org custom-role grant.
		{"role:editor", org1, "authn/oidc_client", "manage"},
	}
	if _, err := e.AddPolicies(rules); err != nil {
		t.Fatalf("AddPolicies(%v) error = %v", rules, err)
	}
	groupings := [][]string{
		// Wildcard hierarchy: owner > admin > manager > member.
		{"role:owner", "role:admin", WildcardDomain},
		{"role:admin", "role:manager", WildcardDomain},
		{"role:manager", "role:member", WildcardDomain},
		// Memberships.
		{"user:u-owner", "role:owner", org1},
		{"user:u-member", "role:member", org1},
		{"user:u-editor", "role:editor", org1},
	}
	if _, err := e.AddGroupingPolicies(groupings); err != nil {
		t.Fatalf("AddGroupingPolicies(%v) error = %v", groupings, err)
	}

	tests := []struct {
		name string
		sub  string
		dom  string
		obj  string
		act  string
		want bool
	}{
		{
			name: "owner inherits member grant through wildcard hierarchy",
			sub:  "user:u-owner", dom: org1, obj: "authz/org", act: "view",
			want: true,
		},
		{
			name: "owner inherits admin wildcard grant",
			sub:  "user:u-owner", dom: org1, obj: "authn/oidc_client", act: "manage",
			want: true,
		},
		{
			name: "member gets wildcard member grant",
			sub:  "user:u-member", dom: org1, obj: "authz/org", act: "view",
			want: true,
		},
		{
			name: "member lacks admin grant",
			sub:  "user:u-member", dom: org1, obj: "authn/oidc_client", act: "manage",
			want: false,
		},
		{
			name: "membership does not leak across organizations",
			sub:  "user:u-owner", dom: org2, obj: "authz/org", act: "view",
			want: false,
		},
		{
			name: "custom role grant applies in its organization",
			sub:  "user:u-editor", dom: org1, obj: "authn/oidc_client", act: "manage",
			want: true,
		},
		{
			name: "custom role grant stays scoped to its organization",
			sub:  "user:u-editor", dom: org2, obj: "authn/oidc_client", act: "manage",
			want: false,
		},
		{
			name: "unknown user denied",
			sub:  "user:u-stranger", dom: org1, obj: "authz/org", act: "view",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := e.Enforce(tt.sub, tt.dom, tt.obj, tt.act)
			if err != nil {
				t.Fatalf("Enforce(%q, %q, %q, %q) error = %v", tt.sub, tt.dom, tt.obj, tt.act, err)
			}
			if got != tt.want {
				t.Errorf("Enforce(%q, %q, %q, %q) = %v, want %v",
					tt.sub, tt.dom, tt.obj, tt.act, got, tt.want)
			}
		})
	}
}

func TestPlatformDomainIsolatedFromWildcardRules(t *testing.T) {
	t.Parallel()

	e, err := NewSyncedEnforcer()
	if err != nil {
		t.Fatalf("NewSyncedEnforcer() error = %v", err)
	}
	if _, err := e.AddPolicies([][]string{
		{"role:member", WildcardDomain, "organization/settings", "write"},
		{"role:platform_admin", PlatformDomain, "platform/policy", "read"},
	}); err != nil {
		t.Fatalf("AddPolicies() error = %v", err)
	}
	if _, err := e.AddGroupingPolicies([][]string{
		{"user:organization-owner", "role:member", "org-1"},
		{"user:platform-admin", "role:platform_admin", PlatformDomain},
	}); err != nil {
		t.Fatalf("AddGroupingPolicies() error = %v", err)
	}

	allowed, err := e.Enforce("user:organization-owner", PlatformDomain, "organization/settings", "write")
	if err != nil {
		t.Fatalf("Enforce wildcard role in platform domain: %v", err)
	}
	if allowed {
		t.Error("organization wildcard grant leaked into platform domain")
	}
	allowed, err = e.Enforce("user:platform-admin", PlatformDomain, "platform/policy", "read")
	if err != nil {
		t.Fatalf("Enforce platform role: %v", err)
	}
	if !allowed {
		t.Error("platform-domain grant was not applied")
	}
}
