package identity

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"sanzi.io/muid/api/proto/event/v1/mail"
	claimspb "sanzi.io/muid/api/proto/shared/v1/claims"
	"sanzi.io/muid/internal/authn/ent"
	"sanzi.io/muid/internal/authn/ent/userref"
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

	emailIntentLogin       = "login"
	emailIntentChangeEmail = "change_email"
)

type EmailIdentityProvider struct {
	otpStore        otp.OTPStore
	transitionStore session.AuthTransitionStore
	pubSub          pubsub.PubSub
	accounts        *account.Accounts
}

func NewEmailIdentityProvider(
	otpStore otp.OTPStore,
	transitionStore session.AuthTransitionStore,
	pubSub pubsub.PubSub,
	accounts *account.Accounts,
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

	intent := input.Intent
	if intent == idn.IntentUnspecified {
		intent = idn.IntentLogin
	}

	email := strings.TrimSpace(strings.ToLower(input.Identifier))

	if intent == idn.IntentLinkAccount {
		return p.startChangeEmail(ctx, input, email)
	}

	sess, err := p.createTransitionSession(ctx, email, emailIntentLogin, "", "")
	if err != nil {
		return idn.StepResult{}, err
	}

	err = p.generateAndSendOTP(ctx, sess.Id, email)
	if err != nil {
		return idn.StepResult{}, err
	}

	return idn.StepResult{
		TransitionId: sess.Id,
		Type:         idn.StepInput,
	}, nil
}

func (p *EmailIdentityProvider) startChangeEmail(
	ctx context.Context,
	input idn.StartInput,
	newEmail string,
) (idn.StepResult, error) {
	linkRes, err := resolveLinkSession(
		ctx,
		p.accounts,
		idn.IntentLinkAccount,
		input.LinkSessionToken,
	)
	if err != nil {
		return idn.StepResult{}, err
	}

	ref, err := p.accounts.Store.DB.UserRef.Get(ctx, linkRes.UserID)
	if err != nil {
		return idn.StepResult{}, err
	}
	if strings.EqualFold(ref.Email, newEmail) {
		return idn.StepResult{}, errors.Join(
			idn.ErrInvalidInput,
			errors.New("new email matches current email"),
		)
	}

	other, err := p.accounts.Store.DB.UserRef.Query().Where(userref.EmailEQ(newEmail)).Only(ctx)
	if err != nil && !ent.IsNotFound(err) {
		return idn.StepResult{}, err
	}
	if other != nil {
		return idn.StepResult{}, idn.ErrEmailAlreadyInUse
	}

	sess, err := p.createTransitionSession(
		ctx,
		newEmail,
		emailIntentChangeEmail,
		linkRes.UserID.String(),
		ref.Email,
	)
	if err != nil {
		return idn.StepResult{}, err
	}

	if err := p.generateAndSendOTP(ctx, sess.Id, newEmail); err != nil {
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
	if idn.FinishRegisterRequested(input.Payload) {
		return p.continueFinishEmailRegister(ctx, input)
	}

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

	emailFlow, ok := sess.Store.EmailFlow()
	if !ok {
		return idn.StepResult{}, idn.ErrInvalidSessionState
	}

	switch emailFlow.Intent {
	case emailIntentChangeEmail:
		return p.continueChangeEmail(ctx, input, sess)
	default:
		return p.continueLogin(ctx, sess)
	}
}

func (p *EmailIdentityProvider) continueChangeEmail(
	ctx context.Context,
	input idn.ContinueInput,
	sess session.AuthSession,
) (idn.StepResult, error) {
	emailFlow, ok := sess.Store.EmailFlow()
	if !ok {
		return idn.StepResult{}, idn.ErrInvalidSessionState
	}

	uid, err := parseUUID(emailFlow.SubjectUserID)
	if err != nil {
		return idn.StepResult{}, errors.Join(idn.ErrInvalidSessionState, err)
	}

	newEmail := emailFlow.Email
	if _, err := p.accounts.Email.ChangeUserEmail(ctx, p.pubSub, uid, newEmail); err != nil {
		return idn.StepResult{}, err
	}

	p.transitionStore.Delete(ctx, sess.Id)

	wire := strings.TrimSpace(input.LinkSessionToken)
	if wire != "" {
		res, err := p.accounts.Session.ResolveSessionToken(ctx, wire)
		if err != nil {
			return idn.StepResult{}, err
		}
		if res.UserID != uid {
			return idn.StepResult{}, idn.ErrLinkUnauthorized
		}
	}

	return idn.StepResult{Type: idn.StepLinked}, nil
}

func (p *EmailIdentityProvider) continueLogin(
	ctx context.Context,
	sess session.AuthSession,
) (idn.StepResult, error) {
	emailFlow, ok := sess.Store.EmailFlow()
	if !ok {
		return idn.StepResult{}, idn.ErrInvalidSessionState
	}
	email := emailFlow.Email

	userID, found, err := p.accounts.Email.LookupUserByEmail(ctx, email)
	if err != nil {
		return idn.StepResult{}, err
	}

	if !found {
		claims := &claimspb.IdentityInformation{}
		claims.SetEmail(email)
		claims.SetEmailVerified(true)
		reg := &idn.RegisterRequired{Identity: claims}

		store := sess.Store.WithRegisterPending(session.RegisterPendingClaimsFromProto(claims))
		if err := p.transitionStore.Update(ctx, sess.Id, store); err != nil {
			return idn.StepResult{}, err
		}

		return idn.StepResult{
			TransitionId:     sess.Id,
			Type:             idn.StepRegisterRequired,
			RegisterRequired: reg,
		}, nil
	}

	p.transitionStore.Delete(ctx, sess.Id)

	return idn.StepResult{
		Type: idn.StepAuthenticated,
		Authenticated: &idn.AuthenticatedIdentity{
			UserID: userID.String(),
		},
	}, nil
}

func (p *EmailIdentityProvider) continueFinishEmailRegister(
	ctx context.Context,
	input idn.ContinueInput,
) (idn.StepResult, error) {
	sess, err := p.transitionStore.Get(ctx, input.TransitionId)
	if err != nil {
		return idn.StepResult{}, errors.Join(idn.ErrSessionNotFound, err)
	}

	pending, ok := sess.Store.PendingRegisterState()
	if !ok || pending.ProvisionedUserID == "" {
		return idn.StepResult{}, idn.ErrInvalidSessionState
	}

	provisioned, err := parseUUID(pending.ProvisionedUserID)
	if err != nil {
		return idn.StepResult{}, errors.Join(idn.ErrInvalidSessionState, err)
	}

	email := strings.TrimSpace(strings.ToLower(pending.Claims.Email))
	if email == "" {
		return idn.StepResult{}, idn.ErrInvalidSessionState
	}

	linked, found, err := p.accounts.Email.LookupUserByEmail(ctx, email)
	if err != nil {
		return idn.StepResult{}, err
	}
	if !found {
		return idn.StepResult{}, errors.Join(
			idn.ErrInvalidSessionState,
			errors.New("email not linked after provision"),
		)
	}

	return finishRegisterAfterLink(ctx, p.transitionStore, sess.Id, linked, provisioned)
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
	email, intent, subjectUserID, oldEmail string,
) (session.AuthSession, error) {
	store := session.EmailOTPStore(session.StepStart, &session.EmailOTPFlow{
		Email:         email,
		Intent:        intent,
		SubjectUserID: subjectUserID,
		OldEmail:      oldEmail,
	})

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
	msg.SetExpiresAt(timestamppb.New(code.ExpiresAt.UTC()))
	msg.SetCreatedAt(timestamppb.New(created_at.UTC()))

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

func parseUUID(s string) (uuid.UUID, error) {
	return uuid.Parse(strings.TrimSpace(s))
}
