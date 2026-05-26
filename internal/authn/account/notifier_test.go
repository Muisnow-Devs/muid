package account

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	mailpb "sanzi.io/muid/api/proto/event/v1/mail"
	"sanzi.io/muid/pkg/shared/pubsub"
	"sanzi.io/muid/pkg/shared/topics"
)

type notifierPubSub struct {
	topic   topics.Topic
	payload []byte
}

func (s *notifierPubSub) Publish(topics.Topic, []byte) error { return nil }

func (s *notifierPubSub) PublishWithOptions(
	topic topics.Topic,
	payload []byte,
	_ pubsub.PublishOptions,
) error {
	s.topic = topic
	s.payload = append([]byte(nil), payload...)
	return nil
}

func (*notifierPubSub) Subscribe(
	context.Context,
	topics.Topic,
	pubsub.SubscribeOptions,
	func(context.Context, []byte) error,
) error {
	return nil
}

func TestNotifyLoginCompleted_publishesLoginAlert(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := openPasskeyTestDB(t)
	defer db.Close()

	userID := uuid.MustParse("550e8400-e29b-41d4-a716-446655440099")
	err := db.UserRef.Create().
		SetID(userID).
		SetEmail("user@example.com").
		Exec(ctx)
	if err != nil {
		t.Fatalf("create user ref: %v", err)
	}

	pub := &notifierPubSub{}
	svc := &notifier{
		store:      &Store{DB: db},
		pubSub:     pub,
		secureLink: "https://example.com/security",
	}

	err = svc.NotifyLoginCompleted(
		ctx,
		userID,
		MailDeliveryPrefs{Locale: "zh-TW", Timezone: "Asia/Taipei"},
		LoginAlertDetails{
			Device:    "Chrome",
			Location:  "Taipei, TW",
			IPAddress: "203.0.113.1",
			UserAgent: "Mozilla/5.0",
		},
	)
	if err != nil {
		t.Fatalf("NotifyLoginCompleted: %v", err)
	}
	if pub.topic != topics.TopicSendLoginAlert {
		t.Fatalf("topic: got %q want %q", pub.topic, topics.TopicSendLoginAlert)
	}

	var ev mailpb.SendLoginAlertEmailEvent
	err = proto.Unmarshal(pub.payload, &ev)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if ev.GetEmail() != "user@example.com" {
		t.Fatalf("email: %q", ev.GetEmail())
	}
	if ev.GetLocale() != "zh-TW" || ev.GetTimezone() != "Asia/Taipei" {
		t.Fatalf("locale/timezone: %q / %q", ev.GetLocale(), ev.GetTimezone())
	}
	if ev.GetDevice() != "Chrome" || ev.GetLocation() != "Taipei, TW" {
		t.Fatalf("device/location: %q / %q", ev.GetDevice(), ev.GetLocation())
	}
	if ev.GetIpAddress() != "203.0.113.1" || ev.GetUserAgent() != "Mozilla/5.0" {
		t.Fatalf("ip/ua: %q / %q", ev.GetIpAddress(), ev.GetUserAgent())
	}
	if ev.GetSecureLink() != "https://example.com/security" {
		t.Fatalf("secure_link: %q", ev.GetSecureLink())
	}
	if ev.GetId() == "" {
		t.Fatal("expected event id")
	}
}

func TestNotifyLoginCompleted_nilPubSub_noOp(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	svc := &notifier{store: &Store{}, pubSub: nil}

	err := svc.NotifyLoginCompleted(ctx, uuid.Nil, MailDeliveryPrefs{}, LoginAlertDetails{})
	if err != nil {
		t.Fatalf("NotifyLoginCompleted: %v", err)
	}
}

func TestNotifyAccountLinked_publishesEvent(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := openPasskeyTestDB(t)
	defer db.Close()

	userID := uuid.MustParse("550e8400-e29b-41d4-a716-446655440088")
	err := db.UserRef.Create().
		SetID(userID).
		SetEmail("linked@example.com").
		Exec(ctx)
	if err != nil {
		t.Fatalf("create user ref: %v", err)
	}

	pub := &notifierPubSub{}
	svc := &notifier{
		store:  &Store{DB: db},
		pubSub: pub,
	}

	err = svc.NotifyAccountLinked(
		ctx,
		userID,
		"google",
		MailDeliveryPrefs{Locale: "zh-TW", Timezone: "Asia/Taipei"},
	)
	if err != nil {
		t.Fatalf("NotifyAccountLinked: %v", err)
	}
	if pub.topic != topics.TopicAccountLinked {
		t.Fatalf("topic: got %q want %q", pub.topic, topics.TopicAccountLinked)
	}

	var ev mailpb.SendAccountLinkedEmailEvent
	err = proto.Unmarshal(pub.payload, &ev)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if ev.GetEmail() != "linked@example.com" {
		t.Fatalf("email: %q", ev.GetEmail())
	}
	if ev.GetProvider() != "google" {
		t.Fatalf("provider: %q", ev.GetProvider())
	}
	if ev.GetLocale() != "zh-TW" || ev.GetTimezone() != "Asia/Taipei" {
		t.Fatalf("locale/timezone: %q / %q", ev.GetLocale(), ev.GetTimezone())
	}
	if ev.GetId() == "" {
		t.Fatal("expected event id")
	}
}

func TestNotifyAccountLinked_nilPubSub_noOp(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	svc := &notifier{store: &Store{}, pubSub: nil}

	err := svc.NotifyAccountLinked(ctx, uuid.Nil, "google", MailDeliveryPrefs{})
	if err != nil {
		t.Fatalf("NotifyAccountLinked: %v", err)
	}
}
