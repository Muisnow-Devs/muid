package account

import (
	"context"
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
	IPAddress  string
	Location   string
	Device     string
	UserAgent  string
	SecureLink string
}

// LoginNotifier publishes login-alert mail events after successful authentication.
type LoginNotifier interface {
	NotifyLoginCompleted(
		ctx context.Context,
		userID uuid.UUID,
		mailPrefs MailDeliveryPrefs,
		details LoginAlertDetails,
	) error
}

type loginAlertService struct {
	store  *Store
	pubSub pubsub.PubSub
}

// NotifyLoginCompleted publishes mail.send.login_alert for the user's email.
func (l *loginAlertService) NotifyLoginCompleted(
	ctx context.Context,
	userID uuid.UUID,
	mailPrefs MailDeliveryPrefs,
	details LoginAlertDetails,
) error {
	if l.pubSub == nil {
		return nil
	}

	ref, err := l.store.DB.UserRef.Get(ctx, userID)
	if ent.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}

	email := ref.Email
	if email == "" {
		return nil
	}

	return publishLoginAlert(l.pubSub, email, mailPrefs, details)
}

func publishLoginAlert(
	pub pubsub.PubSub,
	email string,
	mailPrefs MailDeliveryPrefs,
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
	ev.SetSecureLink(details.SecureLink)
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
