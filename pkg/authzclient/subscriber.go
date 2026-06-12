package authzclient

import (
	"context"
	"slices"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	authzevent "sanzi.io/muid/api/proto/event/v1/authz"
	"sanzi.io/muid/pkg/log"
	"sanzi.io/muid/pkg/shared/pubsub"
	"sanzi.io/muid/pkg/shared/topics"
)

// subscribe wires the policy-change invalidation. The subscription is
// ephemeral and unqueued: every replica must see every event, and missed
// events are healed by the periodic resync.
func (e *Enforcer) subscribe(ctx context.Context) error {
	return e.cfg.PubSub.Subscribe(ctx, topics.TopicAuthzPolicyChanged, pubsub.SubscribeOptions{},
		func(ctx context.Context, message []byte) error {
			ev := &authzevent.PolicyChangedEvent{}
			err := proto.Unmarshal(message, ev)
			if err != nil {
				log.LogUnexpected(ctx, "authzclient policy event unmarshal", err.Error())
				return pubsub.ErrNonRetryable
			}
			e.handleEvent(ctx, ev)
			return nil
		})
}

// handleEvent applies one policy-change event to the local caches.
func (e *Enforcer) handleEvent(ctx context.Context, ev *authzevent.PolicyChangedEvent) {
	switch ev.GetKind() {
	case authzevent.PolicyChangeKind_POLICY_CHANGE_KIND_MEMBERSHIP_CHANGED:
		orgID, err1 := uuid.Parse(ev.GetOrganizationId())
		userID, err2 := uuid.Parse(ev.GetUserId())
		if err1 != nil || err2 != nil {
			return
		}
		e.evictRoles(ctx, userID, orgID)

	case authzevent.PolicyChangeKind_POLICY_CHANGE_KIND_ORGANIZATION_DELETED:
		orgID, err := uuid.Parse(ev.GetOrganizationId())
		if err != nil {
			return
		}
		e.evictOrganization(ctx, orgID)

	case authzevent.PolicyChangeKind_POLICY_CHANGE_KIND_ROLE_GRANTS_CHANGED,
		authzevent.PolicyChangeKind_POLICY_CHANGE_KIND_ROLE_DELETED,
		authzevent.PolicyChangeKind_POLICY_CHANGE_KIND_CONFIG_RELOADED:
		if !e.eventTouchesNamespace(ev) {
			return
		}
		err := e.reloadPolicies(ctx)
		if err != nil {
			log.LogUnexpected(ctx, "authzclient event-driven reload", err.Error())
		}

	default:
	}
}

// eventTouchesNamespace reports whether the event affects this service's
// namespace (an empty namespace list means all).
func (e *Enforcer) eventTouchesNamespace(ev *authzevent.PolicyChangedEvent) bool {
	namespaces := ev.GetNamespaces()
	return len(namespaces) == 0 || slices.Contains(namespaces, e.cfg.Namespace)
}
