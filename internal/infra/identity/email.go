package identity

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"time"

	"google.golang.org/protobuf/proto"
	"sanzi.io/muid/api/proto/event/v1/mail"
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
}

func NewEmailIdentityProvider(
	otpStore otp.OTPStore,
	transitionStore session.AuthTransitionStore,
	pubSub pubsub.PubSub,
) identity.IdentityProvider {
	return &EmailIdentityProvider{
		otpStore:        otpStore,
		transitionStore: transitionStore,
		pubSub:          pubSub,
	}
}

func (p *EmailIdentityProvider) Name() string {
	return "email"
}

func generateOTP() (string, error) {
	const digits = "0123456789"
	b := make([]byte, 6)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			return "", err
		}
		b[i] = digits[n.Int64()]
	}
	return string(b), nil
}

func (p *EmailIdentityProvider) Start(ctx context.Context, input identity.StartInput) (identity.StepResult, error) {
	session, err := p.transitionStore.Create(ctx, input.State)
	if err != nil {
		return identity.StepResult{}, fmt.Errorf("failed to create session: %w", err)
	}

	code, err := generateOTP()
	if err != nil {
		return identity.StepResult{}, fmt.Errorf("failed to generate request code: %w", err)
	}

	if err := p.otpStore.SetOTP(ctx, session.Token, code, 5*time.Minute); err != nil {
		return identity.StepResult{}, fmt.Errorf("failed to store otp: %w", err)
	}

	created_at := time.Now()
	msg := &mail.SendOTPEmailEvent{
		Email:     session.Email,
		Code:      code,
		ExpiresAt: created_at.Add(5 * time.Minute).Unix(),
		CreatedAt: created_at.Unix(),
	}

	msgBytes, err := proto.Marshal(msg)
	if err != nil {
		return identity.StepResult{}, fmt.Errorf("failed to marshal event: %w", err)
	}

	if err := p.pubSub.Publish(event.TopicSendOTP, msgBytes); err != nil {
		return identity.StepResult{}, fmt.Errorf("failed to publish event: %w", err)
	}

	return identity.StepResult{
		Token:     session.Token,
		State:     session.State,
		CreatedAt: created_at.Unix(),
	}, nil
}

func (p *EmailIdentityProvider) Continue(ctx context.Context, input identity.ContinueInput) (identity.StepResult, error) {
	session, err := p.transitionStore.Get(ctx, input.State)
	if err != nil {
		return identity.StepResult{}, fmt.Errorf("failed to get session: %w", err)
	}

	valid, err := p.otpStore.VerifyOTP(ctx, session.Token, input.Code)
	if err != nil {
		return identity.StepResult{}, fmt.Errorf("failed to verify otp: %w", err)
	}
	if !valid {
		return identity.StepResult{}, fmt.Errorf("invalid otp")
	}

	_ = p.transitionStore.Delete(ctx, session.Token)

	return identity.StepResult{
		Token:     session.Token,
		State:     session.State,
		CreatedAt: time.Now().Unix(),
	}, nil
}
