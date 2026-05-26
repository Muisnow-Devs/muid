package identity

import (
	"context"
	"errors"
	"testing"
	"time"

	"sanzi.io/muid/infra/mocked"
	authnkv "sanzi.io/muid/internal/authn/kv"
	idn "sanzi.io/muid/internal/identity"
	"sanzi.io/muid/internal/otp"
	"sanzi.io/muid/internal/session"
	"sanzi.io/muid/pkg/shared/pubsub"
	"sanzi.io/muid/pkg/shared/topics"
)

type stubPubSub struct {
	publishCalls int
}

func (s *stubPubSub) Publish(topics.Topic, []byte) error {
	s.publishCalls++
	return nil
}

func (s *stubPubSub) PublishWithOptions(
	topics.Topic,
	[]byte,
	pubsub.PublishOptions,
) error {
	s.publishCalls++
	return nil
}

func (*stubPubSub) Subscribe(
	context.Context,
	topics.Topic,
	pubsub.SubscribeOptions,
	func(context.Context, []byte) error,
) error {
	return nil
}

func TestEmailIdentityProvider_Continue_Resend_ReusesTransition(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	kv := mocked.NewMockKVStore()
	otpSt := authnkv.NewKVOTPStore(kv, []byte("unit-test-secret"), 0)
	trans := authnkv.NewKVAuthTransitionStore(kv)
	pub := &stubPubSub{}

	prov := &EmailIdentityProvider{
		otpStore:        otpSt,
		transitionStore: trans,
		pubSub:          pub,
	}

	sess, err := trans.Create(
		ctx,
		"email",
		session.EmailOTPStore(session.StepStart, &session.EmailOTPFlow{
			Email: "user@example.com",
		}),
	)
	if err != nil {
		t.Fatalf("create transition: %v", err)
	}

	first, err := otpSt.CreateOTP(ctx, sess.Id, "user@example.com", OTPLifetime)
	if err != nil {
		t.Fatalf("seed otp: %v", err)
	}

	step, err := prov.Continue(ctx, idn.ContinueInput{
		TransitionId: sess.Id,
		Payload: map[string]any{
			EmailPayloadKeyResend: true,
		},
	})
	if err != nil {
		t.Fatalf("resend continue: %v", err)
	}
	if step.Type != idn.StepInput || step.TransitionId != sess.Id {
		t.Fatalf("unexpected step: %#v", step)
	}
	if pub.publishCalls != 1 {
		t.Fatalf("after resend publish calls: %d", pub.publishCalls)
	}

	err = otpSt.VerifyOTP(ctx, sess.Id, first.OTP)
	if err != otp.ErrOTPInvalid {
		t.Fatalf("resend should revoke previous OTP, got %v", err)
	}

	got, err := trans.Get(ctx, sess.Id)
	if err != nil {
		t.Fatalf("get transition after resend: %v", err)
	}
	if got.Id != sess.Id {
		t.Fatalf("transition id changed: %q vs %q", got.Id, sess.Id)
	}
}

func TestEmailIdentityProvider_Continue_ResendWrongStep(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	kv := mocked.NewMockKVStore()
	otpSt := authnkv.NewKVOTPStore(kv, []byte("unit-test-secret"), 0)
	trans := authnkv.NewKVAuthTransitionStore(kv)
	pub := &stubPubSub{}

	prov := &EmailIdentityProvider{
		otpStore:        otpSt,
		transitionStore: trans,
		pubSub:          pub,
	}

	sess, err := trans.Create(
		ctx,
		"email",
		session.EmailOTPStore(session.StepRegister, &session.EmailOTPFlow{
			Email: "user@example.com",
		}),
	)
	if err != nil {
		t.Fatalf("create transition: %v", err)
	}

	_, err = prov.Continue(ctx, idn.ContinueInput{
		TransitionId: sess.Id,
		Payload: map[string]any{
			EmailPayloadKeyResend: true,
		},
	})
	if err == nil {
		t.Fatal("expected error for resend when step is not start")
	}
	if !errors.Is(err, idn.ErrInvalidSessionState) {
		t.Fatalf("expected ErrInvalidSessionState, got %v", err)
	}
}

func TestEmailIdentityProvider_Continue_Resend_RateLimited(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	kv := mocked.NewMockKVStore()
	cooldown := 10 * time.Second
	otpSt := authnkv.NewKVOTPStore(kv, []byte("unit-test-secret"), cooldown)
	trans := authnkv.NewKVAuthTransitionStore(kv)
	pub := &stubPubSub{}

	prov := &EmailIdentityProvider{
		otpStore:        otpSt,
		transitionStore: trans,
		pubSub:          pub,
	}

	sess, err := trans.Create(
		ctx,
		"email",
		session.EmailOTPStore(session.StepStart, &session.EmailOTPFlow{
			Email: "user@example.com",
		}),
	)
	if err != nil {
		t.Fatalf("create transition: %v", err)
	}

	code, err := otpSt.CreateOTP(ctx, sess.Id, "user@example.com", OTPLifetime)
	if err != nil {
		t.Fatalf("seed otp: %v", err)
	}

	_, err = prov.Continue(ctx, idn.ContinueInput{
		TransitionId: sess.Id,
		Payload: map[string]any{
			EmailPayloadKeyResend: true,
		},
	})
	if err == nil {
		t.Fatal("expected rate limit error on immediate resend")
	}
	if !errors.Is(err, otp.ErrOTPSendRateLimited) {
		t.Fatalf("expected ErrOTPSendRateLimited, got %v", err)
	}

	err = otpSt.VerifyOTP(ctx, sess.Id, code.OTP)
	if err != nil {
		t.Fatalf("rate-limited resend should keep original OTP, got %v", err)
	}
}
