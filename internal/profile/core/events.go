package core

import (
	"context"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	profileevent "sanzi.io/muid/api/proto/event/v1/profile"
	idclaims "sanzi.io/muid/api/proto/shared/v1/claims"
	"sanzi.io/muid/pkg/log"
	"sanzi.io/muid/pkg/shared/pubsub"
	"sanzi.io/muid/pkg/shared/topics"
	"sanzi.io/muid/pkg/shared/tracing"
)

// claimsWithPicture builds avatar-change claims; nil when there is no URL to share.
func claimsWithPicture(avatarURL string) *idclaims.IdentityInformation {
	if avatarURL == "" {
		return nil
	}
	c := &idclaims.IdentityInformation{}
	c.SetPicture(avatarURL)
	return c
}

// publishProfileChanged emits a ProfileChangedEvent on the profile.change
// topic. It runs after commit, so failures cannot fail the request; they are
// logged and recorded on the span.
func (m *Manager) publishProfileChanged(
	ctx context.Context,
	userID uuid.UUID,
	responsePaths []string,
	claims *idclaims.IdentityInformation,
) {
	ctx, span := tracing.StartSpan(ctx, "profile.publish_change")
	defer span.End()

	msg := &profileevent.ProfileChangedEvent{}
	msg.SetUserId(userID.String())
	msg.SetChangedFields(&fieldmaskpb.FieldMask{Paths: responsePaths})
	msg.SetOccurredAt(timestamppb.New(time.Now().UTC()))
	if claims != nil {
		msg.SetChanges(claims)
	}

	b, err := proto.Marshal(msg)
	if err != nil {
		span.RecordError(err)
		log.LogUnexpected(ctx, "profile change event marshal", err.Error(), log.UserID(userID))
		return
	}

	err = m.pub.PublishWithOptions(
		topics.TopicProfileChange,
		b,
		pubsub.PublishOptions{
			Reliable:    true,
			RetryPolicy: pubsub.CriticalRetryPolicy(),
		},
	)
	if err != nil {
		span.RecordError(err)
		log.LogUnexpected(ctx, "profile change event publish", err.Error(), log.UserID(userID))
	}
}
