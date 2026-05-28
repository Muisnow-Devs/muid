package authngrpc

import (
	"context"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	mailpb "sanzi.io/muid/api/proto/event/v1/mail"
	"sanzi.io/muid/internal/session"
	"sanzi.io/muid/pkg/shared"
	"sanzi.io/muid/pkg/shared/pubsub"
	"sanzi.io/muid/pkg/shared/topics"
)

func (g *GRPCHandler) notifyLoginCompleted(
	ctx context.Context,
	userID uuid.UUID,
	meta session.SessionMetadata,
) {
	ref, err := g.db.UserRef.Get(ctx, userID)
	if err != nil || ref.Email == "" {
		return
	}

	now := time.Now().UTC()
	ev := &mailpb.SendLoginAlertEmailEvent{}
	ev.SetId(shared.UUIDV7().String())
	ev.SetEmail(ref.Email)
	ev.SetLocale(meta.Locale)
	ev.SetTimezone(meta.Timezone)
	ev.SetIpAddress(meta.IPAddress)
	ev.SetLocation(meta.Location)
	ev.SetDevice(meta.UserAgent)
	ev.SetUserAgent(meta.UserAgent)
	ev.SetSecureLink(g.secureLink)
	ev.SetOccurredAt(timestamppb.New(now))
	ev.SetCreatedAt(timestamppb.New(now))

	b, err := proto.Marshal(ev)
	if err != nil {
		return
	}

	g.pubSub.PublishWithOptions(
		topics.TopicSendLoginAlert,
		b,
		pubsub.PublishOptions{
			Reliable:    true,
			RetryPolicy: pubsub.CriticalRetryPolicy(),
		},
	)
}

func (g *GRPCHandler) notifyAccountLinked(
	ctx context.Context,
	userID uuid.UUID,
	provider string,
	meta session.SessionMetadata,
) {
	ref, err := g.db.UserRef.Get(ctx, userID)
	if err != nil || ref.Email == "" {
		return
	}

	now := time.Now().UTC()
	ev := &mailpb.SendAccountLinkedEmailEvent{}
	ev.SetId(shared.UUIDV7().String())
	ev.SetEmail(ref.Email)
	ev.SetLocale(meta.Locale)
	ev.SetTimezone(meta.Timezone)
	ev.SetProvider(provider)
	ev.SetOccurredAt(timestamppb.New(now))
	ev.SetCreatedAt(timestamppb.New(now))

	b, err := proto.Marshal(ev)
	if err != nil {
		return
	}

	g.pubSub.PublishWithOptions(
		topics.TopicAccountLinked,
		b,
		pubsub.PublishOptions{
			Reliable:    true,
			RetryPolicy: pubsub.CriticalRetryPolicy(),
		},
	)
}

func (g *GRPCHandler) notifyAccountUnlinked(
	ctx context.Context,
	email string,
	provider string,
	meta session.SessionMetadata,
) {
	now := time.Now().UTC()
	ev := &mailpb.SendAccountUnlinkedEmailEvent{}
	ev.SetId(shared.UUIDV7().String())
	ev.SetEmail(email)
	ev.SetLocale(meta.Locale)
	ev.SetTimezone(meta.Timezone)
	ev.SetProvider(provider)
	ev.SetOccurredAt(timestamppb.New(now))
	ev.SetCreatedAt(timestamppb.New(now))

	b, err := proto.Marshal(ev)
	if err != nil {
		return
	}

	g.pubSub.PublishWithOptions(
		topics.TopicAccountUnlinked,
		b,
		pubsub.PublishOptions{
			Reliable:    true,
			RetryPolicy: pubsub.CriticalRetryPolicy(),
		},
	)
}

func (g *GRPCHandler) notifyPasskeyAdded(
	ctx context.Context,
	userID uuid.UUID,
	passkeyName string,
	meta session.SessionMetadata,
) {
	ref, err := g.db.UserRef.Get(ctx, userID)
	if err != nil || ref.Email == "" {
		return
	}

	now := time.Now().UTC()
	ev := &mailpb.SendPasskeyAddedEmailEvent{}
	ev.SetId(shared.UUIDV7().String())
	ev.SetEmail(ref.Email)
	ev.SetLocale(meta.Locale)
	ev.SetTimezone(meta.Timezone)
	ev.SetPasskeyName(passkeyName)
	ev.SetOccurredAt(timestamppb.New(now))
	ev.SetCreatedAt(timestamppb.New(now))

	b, err := proto.Marshal(ev)
	if err != nil {
		return
	}

	g.pubSub.PublishWithOptions(
		topics.TopicPasskeyAdded,
		b,
		pubsub.PublishOptions{
			Reliable:    true,
			RetryPolicy: pubsub.CriticalRetryPolicy(),
		},
	)
}
