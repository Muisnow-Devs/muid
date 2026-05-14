package subscriber

import (
	"context"
	"errors"
	"log"
	"time"

	"google.golang.org/protobuf/proto"

	profileevent "sanzi.io/muid/api/proto/event/v1/profile"
	"sanzi.io/muid/pkg/shared/pubsub"
	"sanzi.io/muid/pkg/shared/topics"
)

// RunProfileSubscriber blocks, unmarshalling profile.change payloads (for side effects / fan-out).
func RunProfileSubscriber(ctx context.Context, ps pubsub.PubSub) error {
	return ps.Subscribe(
		topics.TopicProfileChange,
		pubsub.SubscribeOptions{},
		func(ctx context.Context, message []byte) error {
			var ev profileevent.ProfileChangedEvent
			if err := proto.Unmarshal(message, &ev); err != nil {
				return errors.Join(ErrMalformedProfileChangePayload, err)
			}
			var paths []string
			if cf := ev.GetChangedFields(); cf != nil {
				paths = cf.GetPaths()
			}
			occ := ev.GetOccurredAt()
			occStr := ""
			if occ != nil {
				occStr = occ.AsTime().UTC().Format(time.RFC3339)
			}
			log.Printf(
				"profile.change user_id=%s occurred_at=%s changed_fields=%q changes_set=%v",
				ev.GetUserId(),
				occStr,
				paths,
				ev.HasChanges(),
			)
			return nil
		},
	)
}
