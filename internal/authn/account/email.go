package account

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	mailpb "sanzi.io/muid/api/proto/event/v1/mail"
	profileevent "sanzi.io/muid/api/proto/event/v1/profile"
	claimspb "sanzi.io/muid/api/proto/shared/v1/claims"
	"sanzi.io/muid/internal/authn/ent"
	"sanzi.io/muid/internal/authn/ent/userref"
	idn "sanzi.io/muid/internal/identity"
	"sanzi.io/muid/pkg/shared/pubsub"
	"sanzi.io/muid/pkg/shared/topics"
)

type emailService struct {
	store *Store
}

// LookupUserByEmail returns the authn user id when a UserRef exists for the email.
func (e *emailService) LookupUserByEmail(
	ctx context.Context,
	email string,
) (uuid.UUID, bool, error) {
	ref, err := e.store.DB.UserRef.Query().Where(userref.EmailEQ(email)).Only(ctx)
	if ent.IsNotFound(err) {
		return uuid.Nil, false, nil
	}
	if err != nil {
		return uuid.Nil, false, err
	}
	return ref.ID, true, nil
}

// ChangeUserEmail updates the authn UserRef email and publishes mail + profile events.
func (e *emailService) ChangeUserEmail(
	ctx context.Context,
	pub pubsub.PubSub,
	userID uuid.UUID,
	newEmail string,
) (oldEmail string, err error) {
	newEmail = strings.TrimSpace(strings.ToLower(newEmail))
	if newEmail == "" {
		return "", idn.ErrInvalidInput
	}

	ref, err := e.store.DB.UserRef.Get(ctx, userID)
	if err != nil {
		return "", err
	}
	oldEmail = ref.Email
	if strings.EqualFold(oldEmail, newEmail) {
		return oldEmail, nil
	}

	taken, err := e.store.DB.UserRef.Query().Where(userref.EmailEQ(newEmail)).Only(ctx)
	if err != nil && !ent.IsNotFound(err) {
		return "", err
	}
	if taken != nil && taken.ID != userID {
		return "", idn.ErrEmailAlreadyInUse
	}

	err = e.store.DB.UserRef.UpdateOneID(userID).SetEmail(newEmail).Exec(ctx)
	if err != nil {
		return "", err
	}

	if pub != nil {
		err = publishEmailChanged(pub, oldEmail, newEmail)
		if err != nil {
			return oldEmail, err
		}
		err = publishProfileEmailChange(pub, userID, newEmail)
		if err != nil {
			return oldEmail, err
		}
	}
	return oldEmail, nil
}

func publishEmailChanged(pub pubsub.PubSub, oldEmail, newEmail string) error {
	now := time.Now().UTC()

	ev := &mailpb.SendEmailChangedEvent{}
	ev.SetEmail(newEmail)
	ev.SetOldEmail(oldEmail)
	ev.SetNewEmail(newEmail)
	ev.SetOccurredAt(timestamppb.New(now))
	ev.SetCreatedAt(timestamppb.New(now))

	b, err := proto.Marshal(ev)
	if err != nil {
		return err
	}

	return pub.Publish(topics.TopicEmailChanged, b)
}

func publishProfileEmailChange(pub pubsub.PubSub, userID uuid.UUID, newEmail string) error {
	mask := &fieldmaskpb.FieldMask{Paths: []string{"email"}}

	ch := &claimspb.IdentityInformation{}
	ch.SetEmail(newEmail)

	ev := &profileevent.ProfileChangedEvent{}
	ev.SetUserId(userID.String())
	ev.SetChangedFields(mask)
	ev.SetChanges(ch)
	ev.SetOccurredAt(timestamppb.New(time.Now().UTC()))

	b, err := proto.Marshal(ev)
	if err != nil {
		return err
	}

	return pub.Publish(topics.TopicProfileChange, b)
}
