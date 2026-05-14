package identity

import (
	"context"
	"errors"
	"time"

	"google.golang.org/protobuf/proto"
	"sanzi.io/muid/api/proto/event/v1/mail"
	"sanzi.io/muid/internal/authn/infra/account"
	idn "sanzi.io/muid/internal/identity"
	"sanzi.io/muid/internal/otp"
	"sanzi.io/muid/internal/session"
	"sanzi.io/muid/pkg/shared/pubsub"
	"sanzi.io/muid/pkg/shared/topics"
)

const (
	OTPLifetime         = 5 * time.Minute
	EmailPayloadKeyCode = "code"
)

type EmailIdentityProvider struct {
	otpStore        otp.OTPStore
	transitionStore session.AuthTransitionStore
	pubSub          pubsub.PubSub
	accounts        *account.Services
}

func NewEmailIdentityProvider(
	otpStore otp.OTPStore,
	transitionStore session.AuthTransitionStore,
	pubSub pubsub.PubSub,
	accounts *account.Services,
) idn.IdentityProvider {
	return &EmailIdentityProvider{
		otpStore:        otpStore,
		transitionStore: transitionStore,
		pubSub:          pubSub,
		accounts:        accounts,
	}
}

func (p *EmailIdentityProvider) Name() string {
	return "email"
}

func (p *EmailIdentityProvider) Start(
	ctx context.Context,
	input idn.StartInput,
) (idn.StepResult, error) {
	if err := validateEmailStartInput(input); err != nil {
		return idn.StepResult{}, err
	}

	sess, err := p.createTransitionSession(ctx, input.Identifier)
	if err != nil {
		return idn.StepResult{}, err
	}

	err = p.generateAndSendOTP(ctx, sess.Id, input.Identifier)
	if err != nil {
		return idn.StepResult{}, err
	}

	return idn.StepResult{
		TransitionId: sess.Id,
		Type:         idn.StepInput,
	}, nil
}

func (p *EmailIdentityProvider) Continue(
	ctx context.Context,
	input idn.ContinueInput,
) (idn.StepResult, error) {
	code, err := p.parseEmailContinuePayload(input.Payload)
	if err != nil {
		return idn.StepResult{}, err
	}

	sess, err := p.validateSession(ctx, input.TransitionId)
	if err != nil {
		return idn.StepResult{}, err
	}

	err = p.verifyOTP(ctx, sess.Id, code)
	if err != nil {
		return idn.StepResult{}, err
	}

	if sess.Store.Flow != session.FlowKindEmailOTP || sess.Store.Email == nil {
		return idn.StepResult{}, errors.Join(
			idn.ErrInvalidSessionState,
			errors.New("expected email_otp transition"),
		)
	}

	email := sess.Store.Email.Email
	userID, err := p.accounts.ResolveEmailLogin(ctx, email)
	if err != nil {
		return idn.StepResult{}, err
	}

	authResult, err := p.accounts.IssueAuthenticatedSession(ctx, userID)
	if err != nil {
		return idn.StepResult{}, err
	}

	p.transitionStore.Delete(ctx, sess.Id)

	return idn.StepResult{
		Type:                idn.StepComplete,
		AuthenticatedResult: authResult,
	}, nil
}

func validateEmailStartInput(input idn.StartInput) error {
	if input.Identifier == "" {
		return errors.Join(
			idn.ErrInvalidInput,
			errors.New("missing email identifier"),
		)
	}
	return nil
}

func (p *EmailIdentityProvider) createTransitionSession(
	ctx context.Context,
	email string,
) (session.AuthSession, error) {
	store := session.SessionStore{
		Flow: session.FlowKindEmailOTP,
		Step: AuthStepStart,
		Email: &session.EmailOTPFlow{
			Email: email,
		},
	}

	sess, err := p.transitionStore.Create(ctx, p.Name(), store)
	if err != nil {
		return session.AuthSession{}, err
	}

	return sess, nil
}

func (p *EmailIdentityProvider) generateAndSendOTP(
	ctx context.Context,
	sessionID string,
	email string,
) error {
	code, err := p.otpStore.CreateOTP(ctx, sessionID, OTPLifetime)
	if err != nil {
		return err
	}

	created_at := time.Now()
	msg := &mail.SendOTPEmailEvent{}
	msg.SetEmail(email)
	msg.SetCode(code.OTP)
	msg.SetExpiresAt(code.ExpiresAt.Unix())
	msg.SetCreatedAt(created_at.Unix())

	msgBytes, err := proto.Marshal(msg)
	if err != nil {
		return err
	}

	if err := p.pubSub.Publish(topics.TopicSendOTP, msgBytes); err != nil {
		return err
	}

	return nil
}

func (*EmailIdentityProvider) parseEmailContinuePayload(payload map[string]any) (string, error) {
	code, ok := payload[EmailPayloadKeyCode].(string)
	if !ok || code == "" {
		return "", errors.Join(
			idn.ErrInvalidInput,
			errors.New("missing code in payload"),
		)
	}
	return code, nil
}

func (p *EmailIdentityProvider) validateSession(
	ctx context.Context,
	transitionID string,
) (session.AuthSession, error) {
	sess, err := p.transitionStore.Get(ctx, transitionID)
	if err != nil {
		return session.AuthSession{}, errors.Join(
			idn.ErrSessionNotFound,
			err,
		)
	}
	return sess, nil
}

func (p *EmailIdentityProvider) verifyOTP(
	ctx context.Context,
	sessionID string,
	code string,
) error {
	err := p.otpStore.VerifyOTP(ctx, sessionID, code)
	if errors.Is(err, otp.ErrOTPAuthFailed) {
		return errors.Join(
			idn.ErrAuthenticationFailed,
			err,
		)
	}

	if err != nil {
		return err
	}

	return nil
}
