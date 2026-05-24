package account

import (
	"context"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
	mailpb "sanzi.io/muid/api/proto/event/v1/mail"
	"sanzi.io/muid/internal/authn/ent/userpasskey"
	idn "sanzi.io/muid/internal/identity"
	"sanzi.io/muid/pkg/shared/pubsub"
	"sanzi.io/muid/pkg/shared/topics"
	"sanzi.io/muid/pkg/utils"
)

type passkeyService struct {
	store  *Store
	pubSub pubsub.PubSub
}

// LinkPasskey persists a new WebAuthn credential for the user.
func (p *passkeyService) LinkPasskey(
	ctx context.Context,
	config LinkPasskeyConfig,
) error {
	if len(config.CredentialID) == 0 || len(config.PublicKey) == 0 {
		return idn.ErrInvalidInput
	}

	utils.DefaultIfEmpty(&config.RpID, "localhost")
	utils.DefaultIfEmpty(&config.DeviceType, "multi_device")

	exists, err := p.store.DB.UserPasskey.Query().
		Where(userpasskey.CredentialIDEQ(config.CredentialID)).
		Exist(ctx)
	if err != nil {
		return err
	}
	if exists {
		return idn.ErrPasskeyAlreadyRegistered
	}

	create := p.store.DB.UserPasskey.Create().
		SetUserID(config.UserId).
		SetCredentialID(config.CredentialID).
		SetPublicKey(config.PublicKey).
		SetRpID(config.RpID).
		SetDeviceType(parseDeviceType(config.DeviceType)).
		SetName(config.Name).
		SetBackupEligible(config.BackupEligible).
		SetBackupState(config.BackupState).
		SetSignCount(config.SignCount).
		SetTransports(config.Transports)
	if len(config.AAGUID) > 0 {
		create.SetAaguid(config.AAGUID)
	}

	err = create.Exec(ctx)
	if err != nil {
		return err
	}
	return nil
}

// NotifyPasskeyAdded publishes the passkey-added mail event for the user.
func (p *passkeyService) NotifyPasskeyAdded(
	ctx context.Context,
	userID uuid.UUID,
	passkeyName string,
	mailPrefs MailDeliveryPrefs,
) error {
	if p.pubSub == nil {
		return nil
	}

	ref, err := p.store.DB.UserRef.Get(ctx, userID)
	if err != nil {
		return err
	}

	return publishPasskeyAdded(p.pubSub, ref.Email, passkeyName, mailPrefs)
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

func (p *passkeyService) UpdatePasskeyUsage(
	ctx context.Context,
	config UpdatePasskeyUsageConfig,
) error {
	if len(config.CredentialID) == 0 {
		return idn.ErrInvalidInput
	}
	if config.LastUsedAt.IsZero() {
		config.LastUsedAt = time.Now().UTC()
	}

	err := p.store.DB.UserPasskey.Update().
		Where(userpasskey.CredentialIDEQ(config.CredentialID)).
		SetBackupState(config.BackupState).
		SetSignCount(config.SignCount).
		SetLastUsedAt(config.LastUsedAt).
		Exec(ctx)
	if err != nil {
		return err
	}
	return nil
}

func parseDeviceType(v string) userpasskey.DeviceType {
	switch v {
	case string(userpasskey.DeviceTypeSingleDevice):
		return userpasskey.DeviceTypeSingleDevice
	default:
		return userpasskey.DeviceTypeMultiDevice
	}
}
