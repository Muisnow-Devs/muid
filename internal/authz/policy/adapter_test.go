package policy

import (
	"context"
	"testing"

	_ "github.com/mattn/go-sqlite3"

	"sanzi.io/muid/internal/authz/ent/casbinrule"
	"sanzi.io/muid/internal/authz/ent/enttest"
	"sanzi.io/muid/pkg/shared/authzmodel"
)

func TestEntAdapterLoadPolicy(t *testing.T) {
	client := enttest.Open(t, "sqlite3", "file:authzadapterload?mode=memory&cache=shared&_fk=1")
	defer client.Close()
	ctx := context.Background()

	adapter := NewEntAdapter(client)

	const org = "0195a000-0000-7000-8000-0000000000a1"
	seed := []Rule{
		{Ptype: "p", Values: []string{"role:member", "*", "authz/org", "view"}},
		{Ptype: "p", Values: []string{"role:editor", org, "authn/oidc_client", "manage"}},
		{Ptype: "g", Values: []string{"role:owner", "role:admin", "*"}},
		{Ptype: "g", Values: []string{"role:admin", "role:manager", "*"}},
		{Ptype: "g", Values: []string{"role:manager", "role:member", "*"}},
		{Ptype: "g", Values: []string{"user:u1", "role:owner", org}},
	}
	if err := insertRules(ctx, client.CasbinRule, seed); err != nil {
		t.Fatalf("insertRules(%d rules) error = %v", len(seed), err)
	}

	e, err := authzmodel.NewSyncedEnforcer()
	if err != nil {
		t.Fatalf("NewSyncedEnforcer() error = %v", err)
	}
	e.SetAdapter(adapter)
	if err := e.LoadPolicy(); err != nil {
		t.Fatalf("LoadPolicy() error = %v", err)
	}

	allowed, err := e.Enforce("user:u1", org, "authz/org", "view")
	if err != nil {
		t.Fatalf("Enforce(user:u1) error = %v", err)
	}
	if !allowed {
		t.Error(
			"Enforce(user:u1, org, authz/org, view) = false, want true (owner inherits member via wildcard hierarchy)",
		)
	}

	allowed, err = e.Enforce("user:u2", org, "authz/org", "view")
	if err != nil {
		t.Fatalf("Enforce(user:u2) error = %v", err)
	}
	if allowed {
		t.Error("Enforce(user:u2, org, authz/org, view) = true, want false")
	}
}

func TestEntAdapterWrites(t *testing.T) {
	client := enttest.Open(t, "sqlite3", "file:authzadapterwrites?mode=memory&cache=shared&_fk=1")
	defer client.Close()
	ctx := context.Background()

	adapter := NewEntAdapter(client)

	count := func(t *testing.T) int {
		t.Helper()
		n, err := client.CasbinRule.Query().Count(ctx)
		if err != nil {
			t.Fatalf("count casbin rules: %v", err)
		}
		return n
	}

	t.Run("add and remove single", func(t *testing.T) {
		rule := []string{"role:member", "*", "authz/org", "view"}
		if err := adapter.AddPolicy("p", "p", rule); err != nil {
			t.Fatalf("AddPolicy(%v) error = %v", rule, err)
		}
		if got := count(t); got != 1 {
			t.Fatalf("rule count after AddPolicy = %d, want 1", got)
		}

		// Duplicate insert violates the unique index.
		if err := adapter.AddPolicy("p", "p", rule); err == nil {
			t.Error("AddPolicy(duplicate) error = nil, want unique-constraint error")
		}

		if err := adapter.RemovePolicy("p", "p", rule); err != nil {
			t.Fatalf("RemovePolicy(%v) error = %v", rule, err)
		}
		if got := count(t); got != 0 {
			t.Errorf("rule count after RemovePolicy = %d, want 0", got)
		}
	})

	t.Run("batch add and filtered remove", func(t *testing.T) {
		const (
			org1 = "0195a000-0000-7000-8000-0000000000b1"
			org2 = "0195a000-0000-7000-8000-0000000000b2"
		)
		rules := [][]string{
			{"role:editor", org1, "authn/oidc_client", "manage"},
			{"role:editor", org1, "authn/oidc_client", "view"},
			{"role:editor", org2, "authn/oidc_client", "manage"},
		}
		if err := adapter.AddPolicies("p", "p", rules); err != nil {
			t.Fatalf("AddPolicies(%v) error = %v", rules, err)
		}
		if got := count(t); got != 3 {
			t.Fatalf("rule count after AddPolicies = %d, want 3", got)
		}

		// Remove all p-rules in org1 (filter on the domain column v1).
		if err := adapter.RemoveFilteredPolicy("p", "p", 1, org1); err != nil {
			t.Fatalf("RemoveFilteredPolicy(v1=%s) error = %v", org1, err)
		}
		left, err := client.CasbinRule.Query().Where(casbinrule.V1(org2)).Count(ctx)
		if err != nil {
			t.Fatalf("count org2 rules: %v", err)
		}
		if got := count(t); got != 1 || left != 1 {
			t.Errorf("after filtered remove: total = %d, org2 = %d, want 1 and 1", got, left)
		}

		// Out-of-range filter index is rejected.
		err = adapter.RemoveFilteredPolicy("p", "p", 6, "x")
		if err == nil {
			t.Error("RemoveFilteredPolicy(fieldIndex=6) error = nil, want ErrInvalidRule")
		}
	})
}

func TestEntAdapterSavePolicy(t *testing.T) {
	client := enttest.Open(t, "sqlite3", "file:authzadaptersave?mode=memory&cache=shared&_fk=1")
	defer client.Close()
	ctx := context.Background()

	adapter := NewEntAdapter(client)

	stale := []Rule{
		{Ptype: "p", Values: []string{"role:old", "*", "authz/org", "view"}},
	}
	if err := insertRules(ctx, client.CasbinRule, stale); err != nil {
		t.Fatalf("insertRules(stale) error = %v", err)
	}

	e, err := authzmodel.NewSyncedEnforcer()
	if err != nil {
		t.Fatalf("NewSyncedEnforcer() error = %v", err)
	}
	e.SetAdapter(adapter)
	if _, err := e.AddPolicy("role:member", "*", "authz/org", "view"); err != nil {
		t.Fatalf("AddPolicy(in-memory) error = %v", err)
	}
	if _, err := e.AddGroupingPolicy("role:owner", "role:member", "*"); err != nil {
		t.Fatalf("AddGroupingPolicy(in-memory) error = %v", err)
	}

	if err := e.SavePolicy(); err != nil {
		t.Fatalf("SavePolicy() error = %v", err)
	}

	rows, err := client.CasbinRule.Query().All(ctx)
	if err != nil {
		t.Fatalf("query rules: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("rule count after SavePolicy = %d, want 2 (stale row replaced)", len(rows))
	}
	for _, row := range rows {
		r := ruleFromRow(row)
		if r.Ptype == "p" && r.Values[0] == "role:old" {
			t.Errorf("stale rule %v survived SavePolicy", r)
		}
	}
}
