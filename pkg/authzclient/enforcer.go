// Package authzclient embeds a casbin enforcer inside a consuming service:
// it replicates the service's permission relations (role→permission rules
// and the role hierarchy) from authz, resolves user→role groupings on
// demand with caching, and keeps everything fresh through authz
// policy-change events plus a periodic resync. Decisions then run locally —
// no per-check RPC.
package authzclient

import (
	"context"
	"sync"
	"time"

	"github.com/casbin/casbin/v2"
	"github.com/google/uuid"

	authzpb "sanzi.io/muid/api/proto/authz/v1"
	"sanzi.io/muid/pkg/log"
	"sanzi.io/muid/pkg/shared/authzmodel"
	"sanzi.io/muid/pkg/shared/kv"
	"sanzi.io/muid/pkg/shared/pubsub"
)

const (
	defaultRoleCacheTTL    = 5 * time.Minute
	defaultRefreshInterval = 5 * time.Minute
	policyPageSize         = 1000
)

// Config wires an Enforcer. Client and Namespace are required; PubSub and
// KV are optional (without PubSub staleness is bounded by RefreshInterval
// and RoleCacheTTL alone; without KV the role cache is process-local).
type Config struct {
	// Namespace is the owning service's permission namespace ("authn").
	Namespace string
	// Client is the authz service-to-service client (internal listener).
	Client authzpb.AuthzServiceClient
	// PubSub receives authz.policy.changed events for cache invalidation.
	PubSub pubsub.PubSub
	// KV shares the per-(user, org) role cache across replicas/restarts.
	KV kv.KVStore

	// RoleCacheTTL bounds how long a user's resolved roles are reused.
	RoleCacheTTL time.Duration
	// RefreshInterval is the periodic full namespace-policy resync.
	RefreshInterval time.Duration
}

// rule mirrors one replicated policy rule.
type rule struct {
	ptype  string
	values []string
}

// roleEntry is one cached (user, org) role resolution.
type roleEntry struct {
	roles    []string
	isMember bool
	expires  time.Time
}

// Enforcer is the service-local casbin enforcer. All methods are safe for
// concurrent use after Start.
type Enforcer struct {
	cfg Config
	enf *casbin.SyncedEnforcer

	mu sync.Mutex
	// policyRules is the last replicated namespace policy snapshot.
	policyRules []rule
	// roleCache tracks the user→role g-rules currently injected.
	roleCache map[string]roleEntry
	revision  string
	started   bool

	cancel context.CancelFunc
}

// NewEnforcer validates the config and builds the (empty) local enforcer.
// Call Start to load policies and begin syncing.
func NewEnforcer(cfg Config) (*Enforcer, error) {
	if cfg.Client == nil || !authzmodel.ValidNamespace(cfg.Namespace) {
		return nil, ErrInvalidConfig
	}
	if cfg.RoleCacheTTL <= 0 {
		cfg.RoleCacheTTL = defaultRoleCacheTTL
	}
	if cfg.RefreshInterval <= 0 {
		cfg.RefreshInterval = defaultRefreshInterval
	}

	enf, err := authzmodel.NewSyncedEnforcer()
	if err != nil {
		return nil, err
	}
	return &Enforcer{
		cfg:       cfg,
		enf:       enf,
		roleCache: make(map[string]roleEntry),
	}, nil
}

// Start loads the namespace policies, subscribes to policy-change events,
// and starts the periodic resync. The context bounds the subscription and
// the resync loop.
func (e *Enforcer) Start(ctx context.Context) error {
	err := e.reloadPolicies(ctx)
	if err != nil {
		return err
	}

	runCtx, cancel := context.WithCancel(ctx)
	if e.cfg.PubSub != nil {
		err = e.subscribe(runCtx)
		if err != nil {
			cancel()
			return err
		}
	}
	go e.refreshLoop(runCtx)

	e.mu.Lock()
	e.cancel = cancel
	e.started = true
	e.mu.Unlock()
	return nil
}

// Close stops the resync loop and event handling.
func (e *Enforcer) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.cancel != nil {
		e.cancel()
		e.cancel = nil
	}
	e.started = false
	return nil
}

// Enforce decides a "namespace/resource.action" permission for a user in an
// organization, resolving (and caching) the user's roles first.
func (e *Enforcer) Enforce(
	ctx context.Context,
	userID, organizationID uuid.UUID,
	permission string,
) (bool, error) {
	obj, act, err := authzmodel.SplitPermission(permission)
	if err != nil {
		return false, err
	}
	_, err = e.ensureRoles(ctx, userID, organizationID)
	if err != nil {
		return false, err
	}
	return e.enf.Enforce(
		authzmodel.UserSubject(userID),
		organizationID.String(),
		obj,
		act,
	)
}

// IsMember reports organization membership using the cached role
// resolution.
func (e *Enforcer) IsMember(ctx context.Context, userID, organizationID uuid.UUID) (bool, error) {
	entry, err := e.ensureRoles(ctx, userID, organizationID)
	if err != nil {
		return false, err
	}
	return entry.isMember, nil
}

// reloadPolicies pages the namespace policy snapshot from authz and rebuilds
// the local model (preserving cached memberships).
func (e *Enforcer) reloadPolicies(ctx context.Context) error {
	var rules []rule
	revision := ""
	pageToken := ""
	for {
		req := &authzpb.ListNamespacePoliciesRequest{}
		req.SetNamespace(e.cfg.Namespace)
		req.SetPageSize(policyPageSize)
		req.SetPageToken(pageToken)

		resp, err := e.cfg.Client.ListNamespacePolicies(ctx, req)
		if err != nil {
			return err
		}
		for _, msg := range resp.GetRules() {
			rules = append(rules, rule{ptype: msg.GetPtype(), values: msg.GetValues()})
		}
		revision = resp.GetRevisionId()
		pageToken = resp.GetNextPageToken()
		if pageToken == "" {
			break
		}
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	e.policyRules = rules
	e.revision = revision
	return e.rebuildLocked()
}

// rebuildLocked resets the casbin model from the policy snapshot plus the
// unexpired cached role groupings. Callers hold e.mu.
func (e *Enforcer) rebuildLocked() error {
	e.enf.ClearPolicy()

	now := time.Now()
	var pRules, gRules [][]string
	for _, r := range e.policyRules {
		switch r.ptype {
		case "p":
			pRules = append(pRules, r.values)
		case "g":
			gRules = append(gRules, r.values)
		}
	}
	for key, entry := range e.roleCache {
		if now.After(entry.expires) {
			delete(e.roleCache, key)
			continue
		}
		gRules = append(gRules, entryGroupings(key, entry)...)
	}

	if len(pRules) > 0 {
		_, err := e.enf.AddPolicies(pRules)
		if err != nil {
			return err
		}
	}
	if len(gRules) > 0 {
		_, err := e.enf.AddGroupingPolicies(gRules)
		if err != nil {
			return err
		}
	}
	return nil
}

// refreshLoop is the drift safety net: a full namespace resync every
// RefreshInterval.
func (e *Enforcer) refreshLoop(ctx context.Context) {
	ticker := time.NewTicker(e.cfg.RefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			err := e.reloadPolicies(ctx)
			if err != nil && ctx.Err() == nil {
				log.LogUnexpected(ctx, "authzclient policy refresh", err.Error())
			}
		}
	}
}
