package policy

import (
	"context"
	"time"

	"github.com/casbin/casbin/v2"
	"github.com/google/uuid"

	authzent "sanzi.io/muid/internal/authz/ent"
	"sanzi.io/muid/internal/authz/ent/policyrevision"
	"sanzi.io/muid/pkg/shared"
	"sanzi.io/muid/pkg/shared/authzmodel"
	"sanzi.io/muid/pkg/shared/pubsub"
)

// policyRevisionRowID is the id of the single PolicyRevision row.
const policyRevisionRowID = 1

// Manager owns the authz casbin enforcer and is the only writer of
// casbin_rule and the organization/role/membership tables. Every mutation
// runs the relational rows and the casbin rows in one transaction, applies
// the delta to the in-memory enforcer after commit, and publishes a
// PolicyChangedEvent.
type Manager struct {
	db       *authzent.Client
	enforcer *casbin.SyncedEnforcer
	pubsub   pubsub.PubSub
	cfg      StaticConfig
	// instance identifies this process in published events so replicas can
	// skip self-notifications.
	instance uuid.UUID
}

// ManagerConfig configures NewManager. PubSub may be nil (no events are
// published and replica sync is unavailable; used in tests).
type ManagerConfig struct {
	DB     *authzent.Client
	PubSub pubsub.PubSub
	Config StaticConfig
	// ReloadInterval, when positive, makes the enforcer periodically reload
	// the full policy from storage as a drift safety net.
	ReloadInterval time.Duration
}

// NewManager validates the static configuration, builds the enforcer over
// the casbin_rule adapter, and loads the current policy. Call Close to stop
// the periodic reload.
func NewManager(cfg ManagerConfig) (*Manager, error) {
	err := cfg.Config.Validate()
	if err != nil {
		return nil, err
	}

	e, err := authzmodel.NewSyncedEnforcer()
	if err != nil {
		return nil, err
	}
	e.SetAdapter(NewEntAdapter(cfg.DB))
	// Mutations persist rules themselves inside the domain transaction; the
	// enforcer's policy-management APIs must only touch memory.
	e.EnableAutoSave(false)
	err = e.LoadPolicy()
	if err != nil {
		return nil, err
	}
	if cfg.ReloadInterval > 0 {
		e.StartAutoLoadPolicy(cfg.ReloadInterval)
	}

	return &Manager{
		db:       cfg.DB,
		enforcer: e,
		pubsub:   cfg.PubSub,
		cfg:      cfg.Config,
		instance: shared.UUIDV7(),
	}, nil
}

// Close stops the enforcer's periodic reload.
func (m *Manager) Close() error {
	if m.enforcer.IsAutoLoadingRunning() {
		m.enforcer.StopAutoLoadPolicy()
	}
	return nil
}

// Config returns the validated static configuration.
func (m *Manager) Config() StaticConfig {
	return m.cfg
}

// bumpRevision writes a fresh policy snapshot id inside the mutation
// transaction and returns it.
func bumpRevision(ctx context.Context, tx *authzent.Tx) (uuid.UUID, error) {
	rev := shared.UUIDV7()
	err := tx.PolicyRevision.UpdateOneID(policyRevisionRowID).SetRevision(rev).Exec(ctx)
	if authzent.IsNotFound(err) {
		_, err = tx.PolicyRevision.Create().
			SetID(policyRevisionRowID).
			SetRevision(rev).
			Save(ctx)
	}
	if err != nil {
		return uuid.Nil, err
	}
	return rev, nil
}

// Revision returns the current policy snapshot id (uuid.Nil before the
// first mutation).
func (m *Manager) Revision(ctx context.Context) (uuid.UUID, error) {
	row, err := m.db.PolicyRevision.Query().
		Where(policyrevision.ID(policyRevisionRowID)).
		Only(ctx)
	if authzent.IsNotFound(err) {
		return uuid.Nil, nil
	}
	if err != nil {
		return uuid.Nil, err
	}
	return row.Revision, nil
}

// revisionString renders a revision for proto responses ("" for none).
func revisionString(rev uuid.UUID) string {
	if rev == uuid.Nil {
		return ""
	}
	return rev.String()
}
