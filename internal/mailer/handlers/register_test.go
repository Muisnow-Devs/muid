package handlers

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"sanzi.io/muid/internal/templates"
	"sanzi.io/muid/pkg/log"
	"sanzi.io/muid/pkg/shared/mailer"
	"sanzi.io/muid/pkg/shared/pubsub"
	"sanzi.io/muid/pkg/shared/topics"
)

func TestHandleEvent_logsMailSendAttempt(t *testing.T) {
	t.Parallel()

	sendErr := errors.New("smtp unavailable")
	msg := mailer.Message{
		To:       []string{"user@example.com"},
		Subject:  "Sign in",
		TextBody: "body",
	}

	tests := []struct {
		name            string
		sendErr         error
		wantResult      string
		wantErr         error
		wantWrappedSend bool
		wantNonRetry    bool
	}{
		{
			name:       "success",
			wantResult: "result=success",
		},
		{
			name:            "send failure",
			sendErr:         sendErr,
			wantResult:      "result=failure",
			wantErr:         mailer.ErrEmailSendFailed,
			wantWrappedSend: true,
		},
		{
			name:         "invalid recipient failure",
			sendErr:      mailer.ErrInvalidEmailAddress,
			wantResult:   "result=failure",
			wantErr:      mailer.ErrInvalidEmailAddress,
			wantNonRetry: true,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer
			ctx := log.WithLogger(
				log.WithAttrs(context.Background(), slog.String("scope", tc.name)),
				slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})),
			)
			mail := &recordingMailer{err: tc.sendErr}

			err := handleEvent(
				ctx,
				[]byte("payload"),
				MailerDeps{Mail: mail},
				fakeHandler{msg: msg},
			)

			if mail.sends != 1 {
				t.Fatalf("expected one send, got %d", mail.sends)
			}
			if tc.wantErr == nil && err != nil {
				t.Fatalf("handleEvent() unexpected error: %v", err)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("handleEvent() error %v, want %v", err, tc.wantErr)
			}
			if tc.wantWrappedSend && !errors.Is(err, sendErr) {
				t.Fatalf("handleEvent() error %v should wrap send error", err)
			}
			if tc.wantNonRetry && !errors.Is(err, pubsub.ErrNonRetryable) {
				t.Fatalf("handleEvent() error %v should mark non-retryable", err)
			}
			if !tc.wantNonRetry && errors.Is(err, pubsub.ErrNonRetryable) {
				t.Fatalf("handleEvent() error %v should not mark non-retryable", err)
			}
			if !tc.wantWrappedSend && errors.Is(err, mailer.ErrEmailSendFailed) {
				t.Fatalf("handleEvent() error %v should not add send failure sentinel", err)
			}

			out := buf.String()
			for _, want := range []string{
				`msg="mail send attempt"`,
				"topic=mail.send.otp",
				tc.wantResult,
				"user@example.com",
				"recipient_count=1",
				tc.name,
			} {
				if !strings.Contains(out, want) {
					t.Fatalf("log missing %q in %q", want, out)
				}
			}
		})
	}
}

func TestReliableMailSubscribeOptions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		topic       topics.Topic
		wantDurable string
	}{
		{
			name:        "otp",
			topic:       topics.TopicSendOTP,
			wantDurable: "mailer_mail_send_otp",
		},
		{
			name:        "email changed",
			topic:       topics.TopicEmailChanged,
			wantDurable: "mailer_mail_send_email_changed",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := ReliableMailSubscribeOptions(tc.topic)
			if got.QueueGroup != "mailer" {
				t.Fatalf("QueueGroup = %q, want mailer", got.QueueGroup)
			}
			if !got.Reliable {
				t.Fatal("Reliable = false, want true")
			}
			if got.Durable != tc.wantDurable {
				t.Fatalf("Durable = %q, want %q", got.Durable, tc.wantDurable)
			}
			if got.RetryPolicy != pubsub.CriticalRetryPolicy() {
				t.Fatalf(
					"RetryPolicy = %+v, want %+v",
					got.RetryPolicy,
					pubsub.CriticalRetryPolicy(),
				)
			}
		})
	}
}

func TestSubscribeTopicErrorIncludesCause(t *testing.T) {
	t.Parallel()

	cause := errors.New("nats: configuration requests ack wait to be 5m0s")
	err := &SubscribeTopicError{Topic: topics.TopicSendOTP, Err: cause}

	if !errors.Is(err, cause) {
		t.Fatal("SubscribeTopicError should unwrap cause")
	}
	for _, want := range []string{"subscribe mail.send.otp", cause.Error()} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("Error() = %q, missing %q", err.Error(), want)
		}
	}
}

type fakeHandler struct {
	msg mailer.Message
	err error
}

func (h fakeHandler) Topic() topics.Topic {
	return topics.TopicSendOTP
}

func (h fakeHandler) SubscribeOptions() pubsub.SubscribeOptions {
	return pubsub.SubscribeOptions{}
}

func (h fakeHandler) Handle(
	context.Context,
	templates.MailRenderer,
	[]byte,
) (mailer.Message, error) {
	return h.msg, h.err
}

type recordingMailer struct {
	err   error
	sends int
}

func (m *recordingMailer) Send(context.Context, mailer.Message) error {
	m.sends++
	return m.err
}
