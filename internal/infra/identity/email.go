package identity

import (
	"context"
	"errors"
	"time"

	"google.golang.org/protobuf/proto"
	pbSession "sanzi.io/muid/api/proto/authn/v1/session"
	"sanzi.io/muid/api/proto/event/v1/mail"
	"sanzi.io/muid/internal/authn/ent"
	"sanzi.io/muid/internal/authn/ent/userref"
	"sanzi.io/muid/internal/identity"
	"sanzi.io/muid/internal/otp"
	"sanzi.io/muid/internal/session"
	"sanzi.io/muid/pkg/shared/pubsub"
	"sanzi.io/muid/pkg/shared/topics"
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
	if err := validateEmailStartInput(input); err != nil {
		return identity.StepResult{}, err
	}

	sess, err := p.createTransitionSession(ctx, input.Identifier)
	if err != nil {
		return identity.StepResult{}, err
	}

	err = p.generateAndSendOTP(ctx, sess.Id, input.Identifier)
	if err != nil {
		return identity.StepResult{}, err
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
	code, err := p.parseEmailContinuePayload(input.Payload)
	if err != nil {
		return identity.StepResult{}, err
	}

	sess, err := p.validateSession(ctx, input.TransitionId)
	if err != nil {
		return identity.StepResult{}, err
	}

	err = p.verifyOTP(ctx, sess.Id, code)
	if err != nil {
		return identity.StepResult{}, err
	}

	email := sess.Store.LoginHint
	userId, err := p.findOrCreateUser(ctx, email)
	if err != nil {
		return identity.StepResult{}, err
	}

	p.transitionStore.Delete(ctx, sess.Id)

	return p.completedResult(userId), nil
}

func validateEmailStartInput(input identity.StartInput) error {
	if input.Identifier == "" {
		return errors.Join(
			identity.ErrInvalidInput,
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
		Step:      "start",
		LoginHint: email, // Use LoginHint to store the email address
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
	code, err := p.otpStore.CreateOTP(ctx, sessionID, 5*time.Minute)
	if err != nil {
		return err
	}

	created_at := time.Now()
	msg := &mail.SendOTPEmailEvent{
		Email:     email,
		Code:      code,
		ExpiresAt: created_at.Add(5 * time.Minute).Unix(),
		CreatedAt: created_at.Unix(),
	}

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
	code, ok := payload["code"].(string)
	if !ok || code == "" {
		return "", errors.Join(
			identity.ErrInvalidInput,
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
			identity.ErrSessionNotFound,
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
			identity.ErrAuthenticationFailed,
			err,
		)
	}

	if err != nil {
		return err
	}

	return nil
}

func (p *EmailIdentityProvider) findOrCreateUser(
	ctx context.Context,
	email string,
) (string, error) {
	fedUser, err := p.db.UserRef.Query().
		Where(userref.EmailEQ(email)).
		Only(ctx)

	if ent.IsNotFound(err) {
		//  TODO: Create a new account or link to an existing account based on the claims.
		//        Maybe replace fedId if user created and linked to the federated identity
		//        in the same request?

		panic("unimplemented: account provisioning and linking logic for Email identities")
	} else if err != nil {
		return "", err
	}

	return fedUser.ID.String(), nil
}

func (*EmailIdentityProvider) completedResult(userID string) identity.StepResult {
	return identity.StepResult{
		Type: identity.StepComplete,
		AuthenticatedResult: &pbSession.AuthenticatedResult{
			UserId:    userID,
			AuthLevel: pbSession.AuthLevel_AUTH_LEVEL_MEDIUM,
		},
	}
}
