package subscriber

import (
	"context"
	"errors"
	"log"

	"google.golang.org/protobuf/proto"

	profileevent "sanzi.io/muid/api/proto/event/v1/profile"
	"sanzi.io/muid/pkg/shared/pubsub"
	"sanzi.io/muid/pkg/shared/topics"
)

// RunProfileSubscriber blocks, unmarshalling profile.change payloads (for side effects / fan-out).
func RunProfileSubscriber(ctx context.Context, ps pubsub.PubSub) error {
	return ps.Subscribe(topics.TopicProfileChange, pubsub.SubscribeOptions{}, func(ctx context.Context, message []byte) error {
		var ev profileevent.ProfileChangedEvent
		if err := proto.Unmarshal(message, &ev); err != nil {
			return errors.Join(ErrMalformedProfileChangePayload, err)
		}
		log.Printf("profile.change user_id=%s change_type=%s", ev.GetUserId(), ev.GetChangeType().String())
		return nil
	})
}
