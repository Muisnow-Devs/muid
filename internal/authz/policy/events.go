package policy

import (
	"context"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	authzevent "sanzi.io/muid/api/proto/event/v1/authz"
	"sanzi.io/muid/pkg/log"
	"sanzi.io/muid/pkg/shared/pubsub"
	"sanzi.io/muid/pkg/shared/topics"
)

// policyChange describes a committed mutation for event publishing.
type policyChange struct {
	kind       authzevent.PolicyChangeKind
	orgID      uuid.UUID // Nil when wildcard-domain rules changed
	namespaces []string  // empty = all namespaces
	role       string
	userID     uuid.UUID
	revision   uuid.UUID
}

// publishChange emits a PolicyChangedEvent after a committed mutation.
// Publish failures are logged, not returned: consumers self-heal through
// their periodic resync, and the mutation itself already succeeded.
func (m *Manager) publishChange(ctx context.Context, change policyChange) {
	if m.pubsub == nil {
		return
	}

	ev := &authzevent.PolicyChangedEvent{}
	ev.SetKind(change.kind)
	if change.orgID != uuid.Nil {
		ev.SetOrganizationId(change.orgID.String())
	}
	ev.SetNamespaces(change.namespaces)
	ev.SetRole(change.role)
	if change.userID != uuid.Nil {
		ev.SetUserId(change.userID.String())
	}
	ev.SetRevisionId(revisionString(change.revision))
	ev.SetOriginInstanceId(m.instance.String())
	ev.SetOccurredAt(timestamppb.New(time.Now()))

	payload, err := proto.Marshal(ev)
	if err != nil {
		log.LogUnexpected(ctx, "authz policy event marshal", err.Error())
		return
	}
	err = m.pubsub.PublishWithOptions(topics.TopicAuthzPolicyChanged, payload,
		pubsub.PublishOptions{Reliable: true})
	if err != nil {
		log.LogUnexpected(ctx, "authz policy event publish", err.Error())
	}
}

// StartReplicaSync subscribes to policy-change events and reloads the
// in-memory policy when another authz replica mutated it. Without pub/sub
// the periodic reload (ManagerConfig.ReloadInterval) is the only sync.
func (m *Manager) StartReplicaSync(ctx context.Context) error {
	if m.pubsub == nil {
		return nil
	}
	// Ephemeral, non-queued subscription: every replica must see every
	// event, and missed events are covered by the periodic reload.
	return m.pubsub.Subscribe(ctx, topics.TopicAuthzPolicyChanged, pubsub.SubscribeOptions{},
		func(ctx context.Context, message []byte) error {
			ev := &authzevent.PolicyChangedEvent{}
			err := proto.Unmarshal(message, ev)
			if err != nil {
				log.LogUnexpected(ctx, "authz policy event unmarshal", err.Error())
				return pubsub.ErrNonRetryable
			}
			if ev.GetOriginInstanceId() == m.instance.String() {
				return nil
			}
			err = m.enforcer.LoadPolicy()
			if err != nil {
				log.LogUnexpected(ctx, "authz replica policy reload", err.Error())
				return err
			}
			return nil
		})
}
