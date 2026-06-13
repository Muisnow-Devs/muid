package policy

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"google.golang.org/protobuf/proto"

	authzevent "sanzi.io/muid/api/proto/event/v1/authz"
	authzent "sanzi.io/muid/internal/authz/ent"
	"sanzi.io/muid/internal/authz/ent/casbinrule"
	"sanzi.io/muid/internal/authz/ent/enttest"
	"sanzi.io/muid/pkg/shared/pubsub"
	"sanzi.io/muid/pkg/shared/topics"
)

// fakePubSub records published messages.
type fakePubSub struct {
	mu       sync.Mutex
	messages map[topics.Topic][][]byte
}

func newFakePubSub() *fakePubSub {
	return &fakePubSub{messages: make(map[topics.Topic][][]byte)}
}

func (f *fakePubSub) Publish(topic topics.Topic, message []byte) error {
	return f.PublishWithOptions(topic, message, pubsub.PublishOptions{})
}

func (f *fakePubSub) PublishWithOptions(
	topic topics.Topic,
	message []byte,
	_ pubsub.PublishOptions,
) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.messages[topic] = append(f.messages[topic], message)
	return nil
}

func (f *fakePubSub) Subscribe(
	_ context.Context,
	_ topics.Topic,
	_ pubsub.SubscribeOptions,
	_ func(context.Context, []byte) error,
) error {
	return nil
}

func (f *fakePubSub) events(t *testing.T) []*authzevent.PolicyChangedEvent {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*authzevent.PolicyChangedEvent
	for _, payload := range f.messages[topics.TopicAuthzPolicyChanged] {
		ev := &authzevent.PolicyChangedEvent{}
		if err := proto.Unmarshal(payload, ev); err != nil {
			t.Fatalf("unmarshal published event: %v", err)
		}
		out = append(out, ev)
	}
	return out
}

// newTestManager spins up a Manager on an in-memory sqlite database with the
// embedded default configuration, reconciled.
func newTestManager(t *testing.T, name string) (*Manager, *authzent.Client, *fakePubSub) {
	t.Helper()

	client := enttest.Open(t, "sqlite3", "file:"+name+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() { client.Close() })

	cfg, err := LoadStaticConfig("", "")
	if err != nil {
		t.Fatalf("LoadStaticConfig() error = %v", err)
	}
	ps := newFakePubSub()
	m, err := NewManager(ManagerConfig{DB: client, PubSub: ps, Config: cfg})
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	t.Cleanup(func() { m.Close() })

	if _, _, err := m.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	return m, client, ps
}

func TestReconcileIdempotent(t *testing.T) {
	m, client, _ := newTestManager(t, "authzreconcile")
	ctx := context.Background()

	// newTestManager already reconciled once.
	changed, _, err := m.Reconcile(ctx)
	if err != nil {
		t.Fatalf("Reconcile() second run error = %v", err)
	}
	if changed {
		t.Error("Reconcile() second run changed = true, want false")
	}

	wildcard, err := client.CasbinRule.Query().Count(ctx)
	if err != nil {
		t.Fatalf("count rules: %v", err)
	}
	rules, err := m.cfg.WildcardRules()
	if err != nil {
		t.Fatalf("WildcardRules() error = %v", err)
	}
	if wildcard != len(rules) {
		t.Errorf("stored wildcard rule count = %d, want %d", wildcard, len(rules))
	}

	// A stale wildcard rule is deleted on the next run.
	stale := Rule{Ptype: "p", Values: []string{"role:ghost", "*", "authz/org", "view"}}
	if err := insertRules(ctx, client.CasbinRule, []Rule{stale}); err != nil {
		t.Fatalf("insert stale rule: %v", err)
	}
	changed, _, err = m.Reconcile(ctx)
	if err != nil {
		t.Fatalf("Reconcile() after stale insert error = %v", err)
	}
	if !changed {
		t.Error("Reconcile() after stale insert changed = false, want true")
	}
	n, err := client.CasbinRule.Query().Where(casbinrule.V0("role:ghost")).Count(ctx)
	if err != nil {
		t.Fatalf("count ghost rules: %v", err)
	}
	if n != 0 {
		t.Errorf("ghost rule count after reconcile = %d, want 0", n)
	}
}

func TestOrganizationLifecycleAndHierarchy(t *testing.T) {
	m, client, ps := newTestManager(t, "authzorglifecycle")
	ctx := context.Background()

	owner := uuid.New()
	orgID, err := m.CreateOrganization(ctx, "acme", "test org", owner)
	if err != nil {
		t.Fatalf("CreateOrganization() error = %v", err)
	}

	// Four system roles seeded.
	roles, err := m.Roles(ctx, orgID)
	if err != nil {
		t.Fatalf("Roles() error = %v", err)
	}
	var names []string
	for _, r := range roles {
		names = append(names, r.Name)
		if !r.IsSystem {
			t.Errorf("seeded role %q IsSystem = false, want true", r.Name)
		}
	}
	slices.Sort(names)
	want := []string{"admin", "manager", "member", "owner"}
	if !slices.Equal(names, want) {
		t.Fatalf("seeded roles = %v, want %v", names, want)
	}

	// Owner inherits grants down the hierarchy: role.write is an admin
	// grant, setting.read a member grant.
	for _, permission := range []string{"organization/role.write", "organization/setting.read", "organization/setting.write"} {
		allowed, err := m.Enforce(ctx, owner, orgID, permission)
		if err != nil {
			t.Fatalf("Enforce(owner, %s) error = %v", permission, err)
		}
		if !allowed {
			t.Errorf("Enforce(owner, %s) = false, want true", permission)
		}
	}

	// Effective permissions of the owner contain everything in the catalog.
	permissions, err := m.ImplicitPermissions(ctx, owner, orgID)
	if err != nil {
		t.Fatalf("ImplicitPermissions(owner) error = %v", err)
	}
	for permission := range m.cfg.Catalog() {
		if !slices.Contains(permissions, permission) {
			t.Errorf("ImplicitPermissions(owner) missing %q (got %v)", permission, permissions)
		}
	}

	// Membership is mirrored into a g-rule.
	n, err := client.CasbinRule.Query().
		Where(
			casbinrule.Ptype("g"),
			casbinrule.V0("user:"+owner.String()),
			casbinrule.V2(orgID.String()),
		).
		Count(ctx)
	if err != nil {
		t.Fatalf("count membership g-rules: %v", err)
	}
	if n != 1 {
		t.Errorf("membership g-rule count = %d, want 1", n)
	}

	// Delete wipes members, roles, and scoped rules.
	if err := m.DeleteOrganization(ctx, orgID); err != nil {
		t.Fatalf("DeleteOrganization() error = %v", err)
	}
	left, err := client.CasbinRule.Query().
		Where(casbinrule.Or(
			casbinrule.V1(orgID.String()),
			casbinrule.V2(orgID.String()),
		)).
		Count(ctx)
	if err != nil {
		t.Fatalf("count org rules after delete: %v", err)
	}
	if left != 0 {
		t.Errorf("org-scoped rule count after delete = %d, want 0", left)
	}
	allowed, err := m.Enforce(ctx, owner, orgID, "organization/setting.read")
	if err != nil {
		t.Fatalf("Enforce(after delete) error = %v", err)
	}
	if allowed {
		t.Error("Enforce(owner after org delete) = true, want false")
	}

	// Events were published for create (membership) and delete.
	events := ps.events(t)
	var kinds []authzevent.PolicyChangeKind
	for _, ev := range events {
		kinds = append(kinds, ev.GetKind())
	}
	if !slices.Contains(kinds, authzevent.PolicyChangeKind_POLICY_CHANGE_KIND_MEMBERSHIP_CHANGED) ||
		!slices.Contains(
			kinds,
			authzevent.PolicyChangeKind_POLICY_CHANGE_KIND_ORGANIZATION_DELETED,
		) {
		t.Errorf(
			"published event kinds = %v, want membership-changed and organization-deleted",
			kinds,
		)
	}
}

func TestMemberMutations(t *testing.T) {
	m, client, _ := newTestManager(t, "authzmembers")
	ctx := context.Background()

	owner := uuid.New()
	alice := uuid.New()
	orgID, err := m.CreateOrganization(ctx, "acme", "", owner)
	if err != nil {
		t.Fatalf("CreateOrganization() error = %v", err)
	}

	t.Run("add member and enforce", func(t *testing.T) {
		if err := m.AddMember(ctx, owner, orgID, alice, "member"); err != nil {
			t.Fatalf("AddMember(alice, member) error = %v", err)
		}
		if err := m.AddMember(ctx, owner, orgID, alice, "member"); !errors.Is(
			err,
			ErrAlreadyMember,
		) {
			t.Errorf("AddMember(duplicate) error = %v, want ErrAlreadyMember", err)
		}

		allowed, err := m.Enforce(ctx, alice, orgID, "organization/setting.read")
		if err != nil {
			t.Fatalf("Enforce(alice, org.view) error = %v", err)
		}
		if !allowed {
			t.Error("Enforce(alice member, organization/setting.read) = false, want true")
		}
		allowed, err = m.Enforce(ctx, alice, orgID, "organization/role.write")
		if err != nil {
			t.Fatalf("Enforce(alice, role.manage) error = %v", err)
		}
		if allowed {
			t.Error("Enforce(alice member, organization/role.write) = true, want false")
		}
	})

	t.Run("owner guard rails", func(t *testing.T) {
		// A non-owner cannot grant owner.
		err := m.ChangeMemberRole(ctx, alice, orgID, alice, "owner")
		if !errors.Is(err, ErrPermissionDenied) {
			t.Errorf(
				"ChangeMemberRole(actor=alice, to owner) error = %v, want ErrPermissionDenied",
				err,
			)
		}
		// The last owner cannot be removed or demoted.
		err = m.RemoveMember(ctx, owner, orgID, owner)
		if !errors.Is(err, ErrLastOwner) {
			t.Errorf("RemoveMember(last owner) error = %v, want ErrLastOwner", err)
		}
		err = m.ChangeMemberRole(ctx, owner, orgID, owner, "member")
		if !errors.Is(err, ErrLastOwner) {
			t.Errorf("ChangeMemberRole(last owner to member) error = %v, want ErrLastOwner", err)
		}
	})

	t.Run("change role updates rules", func(t *testing.T) {
		if err := m.ChangeMemberRole(ctx, owner, orgID, alice, "admin"); err != nil {
			t.Fatalf("ChangeMemberRole(alice to admin) error = %v", err)
		}
		allowed, err := m.Enforce(ctx, alice, orgID, "organization/role.write")
		if err != nil {
			t.Fatalf("Enforce(alice admin) error = %v", err)
		}
		if !allowed {
			t.Error("Enforce(alice admin, organization/role.write) = false, want true")
		}

		rows, err := client.CasbinRule.Query().
			Where(
				casbinrule.Ptype("g"),
				casbinrule.V0("user:"+alice.String()),
				casbinrule.V2(orgID.String()),
			).
			All(ctx)
		if err != nil {
			t.Fatalf("query alice g-rules: %v", err)
		}
		if len(rows) != 1 || rows[0].V1 != "role:admin" {
			t.Errorf("alice g-rules = %v, want single role:admin link", rows)
		}
	})

	t.Run("remove member clears rules", func(t *testing.T) {
		if err := m.RemoveMember(ctx, owner, orgID, alice); err != nil {
			t.Fatalf("RemoveMember(alice) error = %v", err)
		}
		if err := m.RemoveMember(ctx, owner, orgID, alice); !errors.Is(err, ErrNotMember) {
			t.Errorf("RemoveMember(again) error = %v, want ErrNotMember", err)
		}
		allowed, err := m.Enforce(ctx, alice, orgID, "organization/setting.read")
		if err != nil {
			t.Fatalf("Enforce(alice removed) error = %v", err)
		}
		if allowed {
			t.Error("Enforce(removed alice, organization/setting.read) = true, want false")
		}
		n, err := client.CasbinRule.Query().
			Where(
				casbinrule.Ptype("g"),
				casbinrule.V0("user:"+alice.String()),
			).
			Count(ctx)
		if err != nil {
			t.Fatalf("count alice g-rules: %v", err)
		}
		if n != 0 {
			t.Errorf("alice g-rule count after removal = %d, want 0", n)
		}
	})
}

func TestCustomRoles(t *testing.T) {
	m, _, _ := newTestManager(t, "authzcustomroles")
	ctx := context.Background()

	owner := uuid.New()
	bob := uuid.New()
	orgID, err := m.CreateOrganization(ctx, "acme", "", owner)
	if err != nil {
		t.Fatalf("CreateOrganization() error = %v", err)
	}

	role, err := m.CreateRole(ctx, orgID, "oidc_editor", "manages oidc clients",
		[]string{"organization/oidc_client.write", "organization/oidc_client.read"})
	if err != nil {
		t.Fatalf("CreateRole(oidc_editor) error = %v", err)
	}
	if len(role.Permissions) != 2 {
		t.Errorf("CreateRole permissions = %v, want 2 entries", role.Permissions)
	}

	if _, err := m.CreateRole(ctx, orgID, "owner", "", nil); !errors.Is(err, ErrRoleExists) {
		t.Errorf("CreateRole(owner) error = %v, want ErrRoleExists", err)
	}
	if _, err := m.CreateRole(ctx, orgID, "ghost_role", "", []string{"nope/not.real"}); !errors.Is(
		err,
		ErrUnknownPermission,
	) {
		t.Errorf("CreateRole(uncataloged perm) error = %v, want ErrUnknownPermission", err)
	}

	if err := m.AddMember(ctx, owner, orgID, bob, "oidc_editor"); err != nil {
		t.Fatalf("AddMember(bob, oidc_editor) error = %v", err)
	}
	allowed, err := m.Enforce(ctx, bob, orgID, "organization/oidc_client.write")
	if err != nil {
		t.Fatalf("Enforce(bob) error = %v", err)
	}
	if !allowed {
		t.Error("Enforce(bob oidc_editor, organization/oidc_client.write) = false, want true")
	}

	t.Run("system role immutable", func(t *testing.T) {
		_, err := m.UpdateRole(ctx, orgID, "admin", "", "", nil)
		if !errors.Is(err, ErrSystemRoleImmutable) {
			t.Errorf("UpdateRole(admin) error = %v, want ErrSystemRoleImmutable", err)
		}
		if err := m.DeleteRole(ctx, orgID, "owner"); !errors.Is(err, ErrSystemRoleImmutable) {
			t.Errorf("DeleteRole(owner) error = %v, want ErrSystemRoleImmutable", err)
		}
	})

	t.Run("rename keeps memberships working", func(t *testing.T) {
		_, err := m.UpdateRole(ctx, orgID, "oidc_editor", "client_admin", "",
			[]string{"organization/oidc_client.write"})
		if err != nil {
			t.Fatalf("UpdateRole(rename) error = %v", err)
		}
		allowed, err := m.Enforce(ctx, bob, orgID, "organization/oidc_client.write")
		if err != nil {
			t.Fatalf("Enforce(bob after rename) error = %v", err)
		}
		if !allowed {
			t.Error("Enforce(bob after role rename) = false, want true")
		}
		// The dropped grant no longer applies.
		allowed, err = m.Enforce(ctx, bob, orgID, "organization/oidc_client.read")
		if err != nil {
			t.Fatalf("Enforce(bob view after rename) error = %v", err)
		}
		if allowed {
			t.Error("Enforce(bob, dropped grant) = true, want false")
		}
	})

	t.Run("delete guarded by assignment", func(t *testing.T) {
		if err := m.DeleteRole(ctx, orgID, "client_admin"); !errors.Is(err, ErrRoleInUse) {
			t.Errorf("DeleteRole(assigned role) error = %v, want ErrRoleInUse", err)
		}
		if err := m.RemoveMember(ctx, owner, orgID, bob); err != nil {
			t.Fatalf("RemoveMember(bob) error = %v", err)
		}
		if err := m.DeleteRole(ctx, orgID, "client_admin"); err != nil {
			t.Fatalf("DeleteRole(client_admin) error = %v", err)
		}
		if err := m.DeleteRole(ctx, orgID, "client_admin"); !errors.Is(err, ErrRoleNotFound) {
			t.Errorf("DeleteRole(again) error = %v, want ErrRoleNotFound", err)
		}
	})
}

func TestNamespacePolicies(t *testing.T) {
	m, _, _ := newTestManager(t, "authznspolicies")
	ctx := context.Background()

	owner := uuid.New()
	orgID, err := m.CreateOrganization(ctx, "acme", "", owner)
	if err != nil {
		t.Fatalf("CreateOrganization() error = %v", err)
	}
	_, err = m.CreateRole(ctx, orgID, "oidc_editor", "", []string{"organization/oidc_client.write"})
	if err != nil {
		t.Fatalf("CreateRole() error = %v", err)
	}

	var rules []Rule
	pageToken := ""
	for {
		page, next, revision, err := m.NamespacePolicies(ctx, "organization", 2, pageToken)
		if err != nil {
			t.Fatalf("NamespacePolicies(organization) error = %v", err)
		}
		if revision == uuid.Nil {
			t.Error("NamespacePolicies revision = Nil, want a snapshot id")
		}
		rules = append(rules, page...)
		if next == "" {
			break
		}
		pageToken = next
	}

	orgObjects := []string{
		"organization/setting",
		"organization/member",
		"organization/role",
		"organization/oidc_client",
	}
	var gotP, gotG int
	for _, r := range rules {
		switch r.Ptype {
		case "p":
			gotP++
			if len(r.Values) < 3 || !slices.Contains(orgObjects, r.Values[2]) {
				t.Errorf("namespace p-rule outside organization namespace: %v", r)
			}
		case "g":
			gotG++
			if r.Values[2] != "*" {
				t.Errorf("namespace g-rule with non-wildcard domain: %v", r)
			}
		}
	}
	// p-rules: the eight default wildcard grants (member read x4, manager
	// member.write, admin role.write + oidc_client.write, owner setting.write)
	// plus the custom role's oidc_client.write grant.
	if gotP != 9 {
		t.Errorf("namespace p-rule count = %d, want 9 (rules: %v)", gotP, rules)
	}
	// g-rules: the three hierarchy links.
	if gotG != 3 {
		t.Errorf("wildcard g-rule count = %d, want 3 (rules: %v)", gotG, rules)
	}

	// Membership g-rules must not leak into namespace policies.
	for _, r := range rules {
		if r.Ptype == "g" && r.Values[2] == orgID.String() {
			t.Errorf("membership g-rule leaked into namespace policies: %v", r)
		}
	}
}

func TestStaticConfigValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		json string
	}{
		{
			name: "missing owner role",
			json: `{"permissions":{"organization":["setting.read"]},"system_roles":["admin"],"role_inheritance":[],"grants":{}}`,
		},
		{
			name: "grant outside catalog",
			json: `{"permissions":{"organization":["setting.read"]},"system_roles":["owner"],"role_inheritance":[],"grants":{"owner":["organization/setting.write"]}}`,
		},
		{
			name: "inheritance with unknown role",
			json: `{"permissions":{},"system_roles":["owner"],"role_inheritance":[["owner","admin"]],"grants":{}}`,
		},
		{
			name: "bad permission entry",
			json: `{"permissions":{"organization":["Setting.Read"]},"system_roles":["owner"],"role_inheritance":[],"grants":{}}`,
		},
		{
			name: "malformed inheritance pair",
			json: `{"permissions":{},"system_roles":["owner"],"role_inheritance":[["owner"]],"grants":{}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := LoadStaticConfig("", tt.json)
			if !errors.Is(err, ErrInvalidConfig) {
				t.Errorf("LoadStaticConfig(%s) error = %v, want ErrInvalidConfig", tt.name, err)
			}
		})
	}

	t.Run("embedded default is valid", func(t *testing.T) {
		t.Parallel()
		if _, err := LoadStaticConfig("", ""); err != nil {
			t.Errorf("LoadStaticConfig(default) error = %v, want nil", err)
		}
	})
}
