package subscriber

import (
	"context"
	"slices"
	"strings"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	profileevent "sanzi.io/muid/api/proto/event/v1/profile"
	"sanzi.io/muid/internal/profile/ent"
	"sanzi.io/muid/pkg/shared/pubsub"
	"sanzi.io/muid/pkg/shared/topics"
)

// Register subscribes profile-side handlers on NATS topics.
func Register(ctx context.Context, ps pubsub.PubSub, db *ent.Client) error {
	return ps.Subscribe(
		ctx,
		topics.TopicProfileChange,
		pubsub.SubscribeOptions{
			QueueGroup:  "profile",
			Reliable:    true,
			Durable:     "profile_email_ref",
			RetryPolicy: pubsub.CriticalRetryPolicy(),
		},
		func(ctx context.Context, payload []byte) error {
			return handleProfileChange(ctx, db, payload)
		},
	)
}

func handleProfileChange(ctx context.Context, db *ent.Client, payload []byte) error {
	var ev profileevent.ProfileChangedEvent
	if err := proto.Unmarshal(payload, &ev); err != nil {
		return err
	}

	if !slices.Contains(ev.GetChangedFields().GetPaths(), "email") {
		return nil
	}

	email := strings.TrimSpace(strings.ToLower(ev.GetChanges().GetEmail()))
	if email == "" {
		return nil
	}

	uid, err := uuid.Parse(strings.TrimSpace(ev.GetUserId()))
	if err != nil {
		return err
	}

	return db.UserProfile.UpdateOneID(uid).
		SetEmailRef(email).
		Exec(ctx)
}
