package identity

import (
	"context"
	"errors"
	"time"

	"google.golang.org/protobuf/proto"
	pbSession "sanzi.io/muid/api/proto/authn/v1/session"
	"sanzi.io/muid/api/proto/event/v1/mail"
	"sanzi.io/muid/internal/authn/ent"
	"sanzi.io/muid/internal/authn/ent/userfederatedidentity"
	"sanzi.io/muid/internal/event"
	"sanzi.io/muid/internal/identity"
	"sanzi.io/muid/internal/otp"
	"sanzi.io/muid/internal/session"
	"sanzi.io/muid/pkg/shared/pubsub"
)

type EmailIdentityProvider struct {
	otpStore        otp.OTPStore
	transitionStore session.AuthTransitionStore
	pubSub          pubsub.PubSub
	db              *ent.Client
}

func NewEmailIdentityProvider(
	otpStore otp.OTPStore,
	transitionStore session.AuthTransitionStore,
	pubSub pubsub.PubSub,
	db *ent.Client,
) identity.IdentityProvider {
	return &EmailIdentityProvider{
		otpStore:        otpStore,
		transitionStore: transitionStore,
		pubSub:          pubSub,
		db:              db,
	}
}

func (p *EmailIdentityProvider) Name() string {
	return "email"
}

func (p *EmailIdentityProvider) Start(
	ctx context.Context,
	input identity.StartInput,
) (identity.StepResult, error) {
	if input.Identifier == "" {
		return identity.StepResult{}, errors.Join(
			identity.ErrInvalidInput,
			errors.New("missing email identifier"),
		)
	}

	store := session.SessionStore{
		Step:      "start",
		LoginHint: input.Identifier, // Use LoginHint to store the email address
	}

	sess, err := p.transitionStore.Create(ctx, p.Name(), store)
	if err != nil {
		return identity.StepResult{}, errors.Join(
			identity.ErrInternal, err)
	}

	code, err := p.otpStore.CreateOTP(ctx, sess.Id, 5*time.Minute)
	if err != nil {
		return identity.StepResult{}, errors.Join(
			identity.ErrInternal,
			errors.New("failed to generate request code"),
		)
	}

	created_at := time.Now()
	msg := &mail.SendOTPEmailEvent{
		Email:     input.Identifier,
		Code:      code,
		ExpiresAt: created_at.Add(5 * time.Minute).Unix(),
		CreatedAt: created_at.Unix(),
	}

	msgBytes, err := proto.Marshal(msg)
	if err != nil {
		return identity.StepResult{}, errors.Join(
			identity.ErrInternal,
			errors.New("failed to marshal event"),
		)
	}

	if err := p.pubSub.Publish(event.TopicSendOTP, msgBytes); err != nil {
		return identity.StepResult{}, errors.Join(
			identity.ErrInternal,
			errors.New("failed to publish event"),
		)
	}

	return identity.StepResult{
		TransitionId: sess.Id,
		Type:         identity.StepInput,
	}, nil
}

func (p *EmailIdentityProvider) Continue(
	ctx context.Context,
	input identity.ContinueInput,
) (identity.StepResult, error) {
	code, ok := input.Payload["code"].(string)
	if !ok {
		return identity.StepResult{}, errors.Join(
			identity.ErrInvalidInput,
			errors.New("missing code in payload"),
		)
	}

	sess, err := p.transitionStore.Get(ctx, input.TransitionId)
	if err != nil {
		return identity.StepResult{}, errors.Join(identity.ErrSessionNotFound, err)
	}

	valid, err := p.otpStore.VerifyOTP(ctx, sess.Id, code)
	if err != nil {
		return identity.StepResult{}, errors.Join(
			identity.ErrAuthenticationFailed,
			errors.New("failed to verify otp"),
		)
	}
	if !valid {
		return identity.StepResult{}, errors.Join(
			identity.ErrAuthenticationFailed,
			errors.New("invalid otp"),
		)
	}

	email := sess.Store.LoginHint

	fedId, err := p.db.UserFederatedIdentity.Query().
		Where(
			userfederatedidentity.ProviderEQ(p.Name()),
			userfederatedidentity.SubjectEQ(email),
		).
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			// TODO: Add placeholder for creating a new account using the email
			// Provide challenge so frontend knows it needs another action before completing
			return identity.StepResult{
				Type: identity.StepChallenge,
				Challenge: map[string]interface{}{
					"action": "create_account",
					"email":  email,
				},
			}, nil
		}
		return identity.StepResult{}, errors.Join(
			identity.ErrInternal, err)
	}

	// Optionally delete the session after successful completion to avoid replay
	_ = p.transitionStore.Delete(ctx, sess.Id)

	return identity.StepResult{
		Type: identity.StepComplete,
		AuthenticatedResult: &pbSession.AuthenticatedResult{
			UserId:    fedId.UserID.String(),
			AuthLevel: pbSession.AuthLevel_AUTH_LEVEL_MEDIUM,
		},
	}, nil
}
