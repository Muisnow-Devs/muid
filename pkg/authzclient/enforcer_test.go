package authzclient

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	authzpb "sanzi.io/muid/api/proto/authz/v1"
	authzevent "sanzi.io/muid/api/proto/event/v1/authz"
	"sanzi.io/muid/infra/mocked"
	"sanzi.io/muid/pkg/shared/pubsub"
	"sanzi.io/muid/pkg/shared/topics"
)

// fakeAuthzClient serves canned namespace policies and per-(org,user) role
// answers, counting calls.
type fakeAuthzClient struct {
	mu          sync.Mutex
	rules       []*authzpb.PolicyRule
	revision    string
	roles       map[string][]string // "<org>:<user>" -> role names
	policyCalls int
	roleCalls   int
}

func policyRule(ptype string, values ...string) *authzpb.PolicyRule {
	rule := &authzpb.PolicyRule{}
	rule.SetPtype(ptype)
	rule.SetValues(values)
	return rule
}

func (f *fakeAuthzClient) CheckOrganizationMembership(
	context.Context, *authzpb.CheckOrganizationMembershipRequest, ...grpc.CallOption,
) (*authzpb.CheckOrganizationMembershipResponse, error) {
	panic("not used")
}

func (f *fakeAuthzClient) CheckOrganizationPermission(
	context.Context, *authzpb.CheckOrganizationPermissionRequest, ...grpc.CallOption,
) (*authzpb.CheckOrganizationPermissionResponse, error) {
	panic("not used")
}

func (f *fakeAuthzClient) CheckPlatformPermission(
	context.Context, *authzpb.CheckPlatformPermissionRequest, ...grpc.CallOption,
) (*authzpb.CheckPlatformPermissionResponse, error) {
	panic("not used")
}

func (f *fakeAuthzClient) ListNamespacePolicies(
	_ context.Context,
	req *authzpb.ListNamespacePoliciesRequest,
	_ ...grpc.CallOption,
) (*authzpb.ListNamespacePoliciesResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.policyCalls++

	out := &authzpb.ListNamespacePoliciesResponse{}
	out.SetRules(f.rules)
	out.SetRevisionId(f.revision)
	return out, nil
}

func (f *fakeAuthzClient) ListUserOrganizationRoles(
	_ context.Context,
	req *authzpb.ListUserOrganizationRolesRequest,
	_ ...grpc.CallOption,
) (*authzpb.ListUserOrganizationRolesResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.roleCalls++

	roles := f.roles[req.GetOrganizationId()+":"+req.GetUserId()]
	out := &authzpb.ListUserOrganizationRolesResponse{}
	out.SetRoles(roles)
	out.SetIsMember(len(roles) > 0)
	return out, nil
}

// fakeSubPubSub delivers published events synchronously to subscribers.
type fakeSubPubSub struct {
	mu       sync.Mutex
	handlers []func(context.Context, []byte) error
}

func (f *fakeSubPubSub) Publish(topic topics.Topic, message []byte) error {
	return f.PublishWithOptions(topic, message, pubsub.PublishOptions{})
}

func (f *fakeSubPubSub) PublishWithOptions(
	_ topics.Topic,
	message []byte,
	_ pubsub.PublishOptions,
) error {
	f.mu.Lock()
	handlers := append([]func(context.Context, []byte) error{}, f.handlers...)
	f.mu.Unlock()
	for _, handler := range handlers {
		_ = handler(context.Background(), message)
	}
	return nil
}

func (f *fakeSubPubSub) PublishWithContext(
	_ context.Context,
	topic topics.Topic,
	message []byte,
	opts pubsub.PublishOptions,
) error {
	return f.PublishWithOptions(topic, message, opts)
}

func (f *fakeSubPubSub) Subscribe(
	_ context.Context,
	_ topics.Topic,
	_ pubsub.SubscribeOptions,
	handler func(context.Context, []byte) error,
) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.handlers = append(f.handlers, handler)
	return nil
}

func publishEvent(t *testing.T, ps *fakeSubPubSub, ev *authzevent.PolicyChangedEvent) {
	t.Helper()
	payload, err := proto.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}
	if err := ps.Publish(topics.TopicAuthzPolicyChanged, payload); err != nil {
		t.Fatalf("publish event: %v", err)
	}
}

const (
	testOrg = "0195a000-0000-7000-8000-0000000000c1"
)

// newTestEnforcer builds a started enforcer over the fake backends. The
// canned policy mirrors the organization namespace of the default config.
func newTestEnforcer(t *testing.T, cfg Config, client *fakeAuthzClient) *Enforcer {
	t.Helper()

	client.rules = []*authzpb.PolicyRule{
		policyRule("p", "role:member", "*", "organization/oidc_client", "read"),
		policyRule("p", "role:admin", "*", "organization/oidc_client", "write"),
		policyRule("g", "role:owner", "role:admin", "*"),
		policyRule("g", "role:admin", "role:manager", "*"),
		policyRule("g", "role:manager", "role:member", "*"),
	}
	client.revision = uuid.NewString()
	if client.roles == nil {
		client.roles = make(map[string][]string)
	}

	cfg.Namespace = "organization"
	cfg.Client = client
	enf, err := NewEnforcer(cfg)
	if err != nil {
		t.Fatalf("NewEnforcer() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := enf.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() { enf.Close() })
	return enf
}

func TestEnforceWithRoleResolution(t *testing.T) {
	client := &fakeAuthzClient{roles: map[string][]string{}}
	owner := uuid.New()
	member := uuid.New()
	stranger := uuid.New()
	orgID := uuid.MustParse(testOrg)
	client.roles[testOrg+":"+owner.String()] = []string{"owner"}
	client.roles[testOrg+":"+member.String()] = []string{"member"}

	enf := newTestEnforcer(t, Config{}, client)
	ctx := context.Background()

	tests := []struct {
		name       string
		userID     uuid.UUID
		permission string
		want       bool
	}{
		{
			name:       "owner inherits manage",
			userID:     owner,
			permission: "organization/oidc_client.write",
			want:       true,
		},
		{
			name:       "owner inherits view",
			userID:     owner,
			permission: "organization/oidc_client.read",
			want:       true,
		},
		{name: "member can view", userID: member, permission: "organization/oidc_client.read", want: true},
		{
			name:       "member cannot manage",
			userID:     member,
			permission: "organization/oidc_client.write",
			want:       false,
		},
		{
			name:       "stranger denied",
			userID:     stranger,
			permission: "organization/oidc_client.read",
			want:       false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := enf.Enforce(ctx, tt.userID, orgID, tt.permission)
			if err != nil {
				t.Fatalf("Enforce(%s) error = %v", tt.permission, err)
			}
			if got != tt.want {
				t.Errorf("Enforce(%s, %s) = %v, want %v", tt.userID, tt.permission, got, tt.want)
			}
		})
	}

	t.Run("membership", func(t *testing.T) {
		isMember, err := enf.IsMember(ctx, member, orgID)
		if err != nil {
			t.Fatalf("IsMember(member) error = %v", err)
		}
		if !isMember {
			t.Error("IsMember(member) = false, want true")
		}
		isMember, err = enf.IsMember(ctx, stranger, orgID)
		if err != nil {
			t.Fatalf("IsMember(stranger) error = %v", err)
		}
		if isMember {
			t.Error("IsMember(stranger) = true, want false")
		}
	})

	t.Run("invalid permission string", func(t *testing.T) {
		_, err := enf.Enforce(ctx, owner, orgID, "organization:oidc_client.write")
		if err == nil {
			t.Error("Enforce(colon permission) error = nil, want invalid-permission error")
		}
	})
}

func TestRoleCaching(t *testing.T) {
	client := &fakeAuthzClient{roles: map[string][]string{}}
	user := uuid.New()
	orgID := uuid.MustParse(testOrg)
	client.roles[testOrg+":"+user.String()] = []string{"member"}

	kvStore := mocked.NewMockKVStore()
	enf := newTestEnforcer(t, Config{KV: kvStore, RoleCacheTTL: time.Hour}, client)
	ctx := context.Background()

	for range 3 {
		if _, err := enf.Enforce(ctx, user, orgID, "organization/oidc_client.read"); err != nil {
			t.Fatalf("Enforce error = %v", err)
		}
	}
	client.mu.Lock()
	calls := client.roleCalls
	client.mu.Unlock()
	if calls != 1 {
		t.Errorf("role RPC calls after repeated Enforce = %d, want 1 (cached)", calls)
	}

	// A second enforcer sharing the KV resolves from the cache without an
	// RPC.
	second := newTestEnforcer(t, Config{KV: kvStore, RoleCacheTTL: time.Hour}, &fakeAuthzClient{
		roles: map[string][]string{},
	})
	allowed, err := second.Enforce(ctx, user, orgID, "organization/oidc_client.read")
	if err != nil {
		t.Fatalf("second enforcer Enforce error = %v", err)
	}
	if !allowed {
		t.Error("second enforcer Enforce = false, want true (roles from shared KV)")
	}
}

func TestRoleCacheTTLExpiry(t *testing.T) {
	client := &fakeAuthzClient{roles: map[string][]string{}}
	user := uuid.New()
	orgID := uuid.MustParse(testOrg)
	client.roles[testOrg+":"+user.String()] = []string{"member"}

	enf := newTestEnforcer(t, Config{RoleCacheTTL: 10 * time.Millisecond}, client)
	ctx := context.Background()

	if _, err := enf.Enforce(ctx, user, orgID, "organization/oidc_client.read"); err != nil {
		t.Fatalf("Enforce error = %v", err)
	}
	time.Sleep(20 * time.Millisecond)
	if _, err := enf.Enforce(ctx, user, orgID, "organization/oidc_client.read"); err != nil {
		t.Fatalf("Enforce after TTL error = %v", err)
	}

	client.mu.Lock()
	calls := client.roleCalls
	client.mu.Unlock()
	if calls != 2 {
		t.Errorf("role RPC calls across TTL expiry = %d, want 2", calls)
	}
}

func TestMembershipChangeEviction(t *testing.T) {
	client := &fakeAuthzClient{roles: map[string][]string{}}
	user := uuid.New()
	orgID := uuid.MustParse(testOrg)
	client.roles[testOrg+":"+user.String()] = []string{"admin"}

	ps := &fakeSubPubSub{}
	kvStore := mocked.NewMockKVStore()
	enf := newTestEnforcer(t, Config{PubSub: ps, KV: kvStore, RoleCacheTTL: time.Hour}, client)
	ctx := context.Background()

	allowed, err := enf.Enforce(ctx, user, orgID, "organization/oidc_client.write")
	if err != nil {
		t.Fatalf("Enforce error = %v", err)
	}
	if !allowed {
		t.Fatal("Enforce(admin) = false, want true")
	}

	// The user is demoted in authz; the event must evict the cached roles.
	client.mu.Lock()
	client.roles[testOrg+":"+user.String()] = []string{"member"}
	client.mu.Unlock()

	ev := &authzevent.PolicyChangedEvent{}
	ev.SetKind(authzevent.PolicyChangeKind_POLICY_CHANGE_KIND_MEMBERSHIP_CHANGED)
	ev.SetOrganizationId(testOrg)
	ev.SetUserId(user.String())
	publishEvent(t, ps, ev)

	allowed, err = enf.Enforce(ctx, user, orgID, "organization/oidc_client.write")
	if err != nil {
		t.Fatalf("Enforce after demotion error = %v", err)
	}
	if allowed {
		t.Error("Enforce(after demotion event) = true, want false")
	}
}

func TestNamespacePolicyReloadOnEvent(t *testing.T) {
	client := &fakeAuthzClient{roles: map[string][]string{}}
	user := uuid.New()
	orgID := uuid.MustParse(testOrg)
	client.roles[testOrg+":"+user.String()] = []string{"member"}

	ps := &fakeSubPubSub{}
	enf := newTestEnforcer(t, Config{PubSub: ps}, client)
	ctx := context.Background()

	allowed, err := enf.Enforce(ctx, user, orgID, "organization/oidc_client.read")
	if err != nil {
		t.Fatalf("Enforce error = %v", err)
	}
	if !allowed {
		t.Fatal("Enforce(member view) = false, want true")
	}

	// The member grant is revoked upstream; a grants-changed event for the
	// organization namespace triggers a reload.
	client.mu.Lock()
	client.rules = []*authzpb.PolicyRule{
		policyRule("p", "role:admin", "*", "organization/oidc_client", "write"),
		policyRule("g", "role:owner", "role:admin", "*"),
	}
	client.revision = uuid.NewString()
	client.mu.Unlock()

	ev := &authzevent.PolicyChangedEvent{}
	ev.SetKind(authzevent.PolicyChangeKind_POLICY_CHANGE_KIND_ROLE_GRANTS_CHANGED)
	ev.SetNamespaces([]string{"organization"})
	publishEvent(t, ps, ev)

	allowed, err = enf.Enforce(ctx, user, orgID, "organization/oidc_client.read")
	if err != nil {
		t.Fatalf("Enforce after reload error = %v", err)
	}
	if allowed {
		t.Error("Enforce(after grant revocation) = true, want false")
	}

	// Events for other namespaces are ignored (no extra policy RPC).
	client.mu.Lock()
	before := client.policyCalls
	client.mu.Unlock()
	other := &authzevent.PolicyChangedEvent{}
	other.SetKind(authzevent.PolicyChangeKind_POLICY_CHANGE_KIND_ROLE_GRANTS_CHANGED)
	other.SetNamespaces([]string{"profile"})
	publishEvent(t, ps, other)
	client.mu.Lock()
	after := client.policyCalls
	client.mu.Unlock()
	if after != before {
		t.Errorf("policy RPC calls after foreign-namespace event = %d, want %d", after, before)
	}
}

func TestOrganizationDeletedEviction(t *testing.T) {
	client := &fakeAuthzClient{roles: map[string][]string{}}
	user := uuid.New()
	orgID := uuid.MustParse(testOrg)
	client.roles[testOrg+":"+user.String()] = []string{"member"}

	ps := &fakeSubPubSub{}
	enf := newTestEnforcer(t, Config{PubSub: ps, RoleCacheTTL: time.Hour}, client)
	ctx := context.Background()

	if _, err := enf.Enforce(ctx, user, orgID, "organization/oidc_client.read"); err != nil {
		t.Fatalf("Enforce error = %v", err)
	}

	// The org disappears in authz.
	client.mu.Lock()
	delete(client.roles, testOrg+":"+user.String())
	client.mu.Unlock()

	ev := &authzevent.PolicyChangedEvent{}
	ev.SetKind(authzevent.PolicyChangeKind_POLICY_CHANGE_KIND_ORGANIZATION_DELETED)
	ev.SetOrganizationId(testOrg)
	publishEvent(t, ps, ev)

	allowed, err := enf.Enforce(ctx, user, orgID, "organization/oidc_client.read")
	if err != nil {
		t.Fatalf("Enforce after org delete error = %v", err)
	}
	if allowed {
		t.Error("Enforce(after organization-deleted event) = true, want false")
	}
}

func TestNotStarted(t *testing.T) {
	t.Parallel()

	enf, err := NewEnforcer(Config{Namespace: "organization", Client: &fakeAuthzClient{}})
	if err != nil {
		t.Fatalf("NewEnforcer() error = %v", err)
	}
	_, err = enf.Enforce(context.Background(), uuid.New(), uuid.New(), "organization/oidc_client.read")
	if err == nil {
		t.Error("Enforce(before Start) error = nil, want ErrNotStarted")
	}
}
