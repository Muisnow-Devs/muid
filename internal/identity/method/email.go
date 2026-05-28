package method

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
	"sanzi.io/muid/api/proto/event/v1/mail"
	"sanzi.io/muid/api/proto/shared/v1/claims"
	identitystore "sanzi.io/muid/internal/identity/store"
	"sanzi.io/muid/internal/otp"
	"sanzi.io/muid/internal/session"
	"sanzi.io/muid/pkg/shared/authn"
	"sanzi.io/muid/pkg/shared/pubsub"
	"sanzi.io/muid/pkg/shared/topics"
	"sanzi.io/muid/pkg/shared/tracing"
)

const (
	OTPLifetime = 5 * time.Minute
)

type EmailOTPCodePayload struct {
	Code string
}

func (EmailOTPCodePayload) PayloadKind() string {
	return "email_code"
}

type EmailOTPResendPayload struct{}

func (EmailOTPResendPayload) PayloadKind() string {
	return "email_resend"
}

// EmailOTPMethod handles OTP-based email authentication. It has no direct
// database dependency; identity persistence is delegated to the injected store.
type EmailOTPMethod struct {
	identityStore   identitystore.IdentityStore
	otpStore        otp.OTPStore
	transitionStore session.AuthTransitionStore
	pubSub          pubsub.PubSub
	cooldown        time.Duration
}

func NewEmailOTPMethod(
	identityStore identitystore.IdentityStore,
	otpStore otp.OTPStore,
	transitionStore session.AuthTransitionStore,
	pubSub pubsub.PubSub,
	cooldownSeconds int,
) IdentityMethod {
	cooldown := time.Duration(cooldownSeconds) * time.Second
	if cooldown < 0 {
		cooldown = 0
	}
	return &EmailOTPMethod{
		identityStore:   identityStore,
		otpStore:        otpStore,
		transitionStore: transitionStore,
		pubSub:          pubSub,
		cooldown:        cooldown,
	}
}

func (m *EmailOTPMethod) Name() string { return "email" }

func (m *EmailOTPMethod) Cooldown() time.Duration { return m.cooldown }

func (m *EmailOTPMethod) Start(
	ctx context.Context,
	req StartRequest,
) (Step, error) {
	email := strings.TrimSpace(strings.ToLower(req.Identifier))
	if email == "" {
		return &FailureStep{
			Code:    authn.ErrCodeInvalidInput,
			Message: "missing email identifier",
		}, nil
	}

	store := session.SessionStore{
		Flow:     &session.EmailOTPFlow{Email: email},
		Intent:   req.Intent,
		Metadata: req.Metadata,
	}
	sess, err := m.transitionStore.Create(ctx, m.Name(), store)
	if err != nil {
		return nil, err
	}

	if err = m.generateAndSendOTP(ctx, sess.Id.String(), email, req.Metadata); err != nil {
		return nil, err
	}

	parsedTid, err := uuid.Parse(sess.Id.String())
	if err != nil {
		return nil, err
	}

	ev := &mail.SendOTPEmailEvent{}
	ev.SetEmail(maskEmail(email))

	return ChallengeStep{
		TransitionId: parsedTid,
		Challenge:    ev,
	}, nil
}

func (m *EmailOTPMethod) Continue(
	ctx context.Context,
	req ContinueRequest,
) (Step, error) {
	tid := req.TransitionId
	sess, err := m.transitionStore.Get(ctx, tid)
	if err != nil {
		if errors.Is(err, session.ErrSessionNotFound) {
			return &FailureStep{
				Code:    authn.ErrCodeTransitionNotFound,
				Message: "transition not found",
			}, nil
		}
		if errors.Is(err, session.ErrSessionExpired) {
			return &FailureStep{
				Code:    authn.ErrCodeTransitionExpired,
				Message: "transition expired",
			}, nil
		}
		return nil, err
	}

	emailFlow, ok := sess.Store.Flow.(*session.EmailOTPFlow)
	if !ok {
		return &FailureStep{
			Code:    authn.ErrCodeInvalidSessionState,
			Message: "invalid email flow state",
		}, nil
	}

	switch payload := req.Payload.(type) {
	case EmailOTPCodePayload:
		if err := m.otpStore.VerifyOTP(ctx, tid.String(), payload.Code); err != nil {
			if errors.Is(err, otp.ErrOTPAuthFailed) {
				return &FailureStep{Code: authn.ErrCodeAuthenticationFailed, Message: "invalid OTP code"}, nil
			}
			return nil, err
		}

		claimsInfo := &claims.IdentityInformation{}
		claimsInfo.SetEmail(emailFlow.Email)
		claimsInfo.SetEmailVerified(true)

		return &VerifiedStep{
			Identity: VerifiedIdentity{
				Provider:   m.Name(),
				Subject:    emailFlow.Email,
				UserClaims: claimsInfo,
				IdentityClaims: identitystore.EmailIdentityClaims{
					Email:         emailFlow.Email,
					EmailVerified: true,
				},
				Store: m.identityStore,
			},
		}, nil

	case EmailOTPResendPayload:
		if err := m.generateAndSendOTP(ctx, tid.String(), emailFlow.Email, sess.Store.Metadata); err != nil {
			if errors.Is(err, otp.ErrOTPSendRateLimited) {
				return &FailureStep{Code: authn.ErrCodeRateLimited, Message: "OTP send rate limited; try again later"}, nil
			}
			return nil, err
		}

		ev := &mail.SendOTPEmailEvent{}
		ev.SetEmail(maskEmail(emailFlow.Email))

		return ChallengeStep{
			TransitionId: req.TransitionId,
			Challenge:    ev,
		}, nil

	default:
		return &FailureStep{Code: authn.ErrCodeInvalidInput, Message: "unsupported email proof payload"}, nil
	}
}

func (m *EmailOTPMethod) generateAndSendOTP(
	ctx context.Context,
	sessionID string,
	email string,
	meta session.SessionMetadata,
) error {
	code, err := m.otpStore.CreateOTP(ctx, sessionID, email, OTPLifetime)
	if err != nil {
		return err
	}

	now := time.Now()
	msg := &mail.SendOTPEmailEvent{}
	msg.SetEmail(email)
	msg.SetLocale(meta.Locale)
	msg.SetTimezone(meta.Timezone)
	msg.SetCode(code.OTP)
	msg.SetExpiresAt(timestamppb.New(code.ExpiresAt.UTC()))
	msg.SetCreatedAt(timestamppb.New(now.UTC()))

	msgBytes, err := proto.Marshal(msg)
	if err != nil {
		return err
	}

	ctx, span := tracing.StartSpan(ctx, "authn.otp.publish")
	defer span.End()

	return m.pubSub.PublishWithOptions(
		topics.TopicSendOTP,
		msgBytes,
		pubsub.PublishOptions{
			Reliable:    true,
			RetryPolicy: pubsub.CriticalRetryPolicy(),
		},
	)
}

func maskEmail(email string) string {
	email = strings.TrimSpace(email)
	at := strings.LastIndex(email, "@")
	if at <= 0 || at == len(email)-1 {
		return "***"
	}
	local, dom := email[:at], email[at+1:]
	if len(local) <= 2 {
		return "**@" + dom
	}
	return local[:1] + "***" + local[len(local)-1:] + "@" + dom
}
