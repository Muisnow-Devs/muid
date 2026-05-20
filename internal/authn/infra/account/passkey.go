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
)

type passkeyService struct {
	store *Store
}

// LinkPasskey persists a new WebAuthn credential for the user.
func (p *passkeyService) LinkPasskey(
	ctx context.Context,
	pub pubsub.PubSub,
	userID uuid.UUID,
	credentialID, publicKey []byte,
	rpID, deviceType, name string,
) error {
	if len(credentialID) == 0 || len(publicKey) == 0 {
		return idn.ErrInvalidInput
	}
	if rpID == "" {
		rpID = "localhost"
	}
	if deviceType == "" {
		deviceType = "multi_device"
	}

	exists, err := p.store.DB.UserPasskey.Query().
		Where(userpasskey.CredentialIDEQ(credentialID)).
		Exist(ctx)
	if err != nil {
		return err
	}
	if exists {
		return idn.ErrPasskeyAlreadyRegistered
	}

	err = p.store.DB.UserPasskey.Create().
		SetUserID(userID).
		SetCredentialID(credentialID).
		SetPublicKey(publicKey).
		SetRpID(rpID).
		SetDeviceType(parseDeviceType(deviceType)).
		SetName(name).
		Exec(ctx)
	if err != nil {
		return err
	}

	if pub == nil {
		return nil
	}
	ref, err := p.store.DB.UserRef.Get(ctx, userID)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	ev := &mailpb.SendPasskeyAddedEmailEvent{}
	ev.SetEmail(ref.Email)
	ev.SetPasskeyName(name)
	ev.SetOccurredAt(timestamppb.New(now))
	ev.SetCreatedAt(timestamppb.New(now))
	b, err := proto.Marshal(ev)
	if err != nil {
		return err
	}
	return pub.Publish(topics.TopicPasskeyAdded, b)
}

func parseDeviceType(v string) userpasskey.DeviceType {
	switch v {
	case string(userpasskey.DeviceTypeSingleDevice):
		return userpasskey.DeviceTypeSingleDevice
	default:
		return userpasskey.DeviceTypeMultiDevice
	}
}
