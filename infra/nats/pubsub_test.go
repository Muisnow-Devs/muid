package nats

import (
	"testing"

	"sanzi.io/muid/pkg/shared/pubsub"
	"sanzi.io/muid/pkg/shared/topics"
)

func TestReliableNames(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		topic       topics.Topic
		opts        pubsub.SubscribeOptions
		wantStream  string
		wantDurable string
	}{
		{
			name:        "topic becomes stream name",
			topic:       topics.TopicEmailChanged,
			wantStream:  "MUID_MAIL_SEND_EMAIL_CHANGED",
			wantDurable: "MUID_MAIL_SEND_EMAIL_CHANGED_DURABLE",
		},
		{
			name:        "explicit durable wins",
			topic:       topics.TopicProfileChange,
			opts:        pubsub.SubscribeOptions{Durable: "profile_email_ref"},
			wantStream:  "MUID_PROFILE_CHANGE",
			wantDurable: "profile_email_ref",
		},
		{
			name:        "queue group contributes durable default",
			topic:       topics.TopicSendOTP,
			opts:        pubsub.SubscribeOptions{QueueGroup: "mailer"},
			wantStream:  "MUID_MAIL_SEND_OTP",
			wantDurable: "MUID_MAIL_SEND_OTP_MAILER",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := streamName(tc.topic); got != tc.wantStream {
				t.Fatalf("streamName() = %q, want %q", got, tc.wantStream)
			}
			if got := durableName(tc.topic, tc.opts); got != tc.wantDurable {
				t.Fatalf("durableName() = %q, want %q", got, tc.wantDurable)
			}
		})
	}
}
