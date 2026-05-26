package account

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
	mailpb "sanzi.io/muid/api/proto/event/v1/mail"
	"sanzi.io/muid/internal/authn/ent"
	"sanzi.io/muid/pkg/shared"
	"sanzi.io/muid/pkg/shared/pubsub"
	"sanzi.io/muid/pkg/shared/topics"
)

// LoginAlertDetails carries optional client context for login-alert mail templates.
type LoginAlertDetails struct {
	IPAddress string
	Location  string
	Device    string
	UserAgent string
}

// Notifier publishes authn-related mail events after successful authentication flows.
type Notifier interface {
	NotifyLoginCompleted(
		ctx context.Context,
		userID uuid.UUID,
		mailPrefs MailDeliveryPrefs,
		details LoginAlertDetails,
	) error
	NotifyAccountLinked(
		ctx context.Context,
		userID uuid.UUID,
		provider string,
		mailPrefs MailDeliveryPrefs,
	) error
	NotifyPasskeyAdded(
		ctx context.Context,
		userID uuid.UUID,
		passkeyName string,
		mailPrefs MailDeliveryPrefs,
	) error
}

type notifier struct {
	store      *Store
	pubSub     pubsub.PubSub
	secureLink string
}

// NotifyLoginCompleted publishes mail.send.login_alert for the user's email.
func (n *notifier) NotifyLoginCompleted(
	ctx context.Context,
	userID uuid.UUID,
	mailPrefs MailDeliveryPrefs,
	details LoginAlertDetails,
) error {
	if n.pubSub == nil {
		return nil
	}

	email, err := n.userEmail(ctx, userID)
	if err != nil {
		return err
	}
	if email == "" {
		return nil
	}

	return publishLoginAlert(n.pubSub, email, mailPrefs, n.secureLink, details)
}

// NotifyAccountLinked publishes mail.send.account_linked for the user's email.
func (n *notifier) NotifyAccountLinked(
	ctx context.Context,
	userID uuid.UUID,
	provider string,
	mailPrefs MailDeliveryPrefs,
) error {
	if n.pubSub == nil {
		return nil
	}

	email, err := n.userEmail(ctx, userID)
	if err != nil {
		return err
	}
	if email == "" {
		return nil
	}

	return publishAccountLinked(n.pubSub, email, provider, mailPrefs)
}

// NotifyPasskeyAdded publishes mail.send.passkey_added for the user's email.
func (n *notifier) NotifyPasskeyAdded(
	ctx context.Context,
	userID uuid.UUID,
	passkeyName string,
	mailPrefs MailDeliveryPrefs,
) error {
	if n.pubSub == nil {
		return nil
	}

	email, err := n.userEmail(ctx, userID)
	if err != nil {
		return err
	}
	if email == "" {
		return nil
	}

	return publishPasskeyAdded(n.pubSub, email, passkeyName, mailPrefs)
}

func (n *notifier) userEmail(ctx context.Context, userID uuid.UUID) (string, error) {
	ref, err := n.store.DB.UserRef.Get(ctx, userID)
	if ent.IsNotFound(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return ref.Email, nil
}

func publishLoginAlert(
	pub pubsub.PubSub,
	email string,
	mailPrefs MailDeliveryPrefs,
	secureLink string,
	details LoginAlertDetails,
) error {
	now := time.Now().UTC()

	ev := &mailpb.SendLoginAlertEmailEvent{}
	ev.SetId(shared.UUIDV7().String())
	ev.SetEmail(email)
	ev.SetLocale(mailPrefs.NormalizedLocale())
	ev.SetTimezone(mailPrefs.NormalizedTimezone())
	ev.SetIpAddress(details.IPAddress)
	ev.SetLocation(details.Location)
	ev.SetDevice(details.Device)
	ev.SetUserAgent(details.UserAgent)
	ev.SetSecureLink(secureLink)
	ev.SetOccurredAt(timestamppb.New(now))
	ev.SetCreatedAt(timestamppb.New(now))

	b, err := proto.Marshal(ev)
	if err != nil {
		return err
	}

	return pub.PublishWithOptions(
		topics.TopicSendLoginAlert,
		b,
		pubsub.PublishOptions{
			Reliable:    true,
			RetryPolicy: pubsub.CriticalRetryPolicy(),
		},
	)
}

func publishAccountLinked(
	pub pubsub.PubSub,
	email, provider string,
	mailPrefs MailDeliveryPrefs,
) error {
	now := time.Now().UTC()

	ev := &mailpb.SendAccountLinkedEmailEvent{}
	ev.SetId(shared.UUIDV7().String())
	ev.SetEmail(email)
	ev.SetLocale(mailPrefs.NormalizedLocale())
	ev.SetTimezone(mailPrefs.NormalizedTimezone())
	ev.SetProvider(strings.TrimSpace(provider))
	ev.SetOccurredAt(timestamppb.New(now))
	ev.SetCreatedAt(timestamppb.New(now))

	b, err := proto.Marshal(ev)
	if err != nil {
		return err
	}

	return pub.PublishWithOptions(
		topics.TopicAccountLinked,
		b,
		pubsub.PublishOptions{
			Reliable:    true,
			RetryPolicy: pubsub.CriticalRetryPolicy(),
		},
	)
}

func publishPasskeyAdded(
	pub pubsub.PubSub,
	email, passkeyName string,
	mailPrefs MailDeliveryPrefs,
) error {
	now := time.Now().UTC()

	ev := &mailpb.SendPasskeyAddedEmailEvent{}
	ev.SetEmail(email)
	ev.SetLocale(mailPrefs.NormalizedLocale())
	ev.SetTimezone(mailPrefs.NormalizedTimezone())
	ev.SetPasskeyName(passkeyName)
	ev.SetOccurredAt(timestamppb.New(now))
	ev.SetCreatedAt(timestamppb.New(now))

	b, err := proto.Marshal(ev)
	if err != nil {
		return err
	}
	return pub.PublishWithOptions(
		topics.TopicPasskeyAdded,
		b,
		pubsub.PublishOptions{
			Reliable:    true,
			RetryPolicy: pubsub.CriticalRetryPolicy(),
		},
	)
}
