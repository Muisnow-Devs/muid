package nats

import (
	"context"
	"os"
	"testing"
	"time"

	"sanzi.io/muid/pkg/shared/pubsub"
	"sanzi.io/muid/pkg/shared/topics"
)

func TestReliableSubscribeRebindsDurableConsumer(t *testing.T) {
	natsURL := os.Getenv("MUID_NATS_TEST_URL")
	if natsURL == "" {
		t.Skip("MUID_NATS_TEST_URL is not set")
	}

	topic := topics.Topic("test.mail.rebind." + time.Now().UTC().Format("20060102150405.000000000"))
	opts := pubsub.SubscribeOptions{
		QueueGroup:  "mailer",
		Reliable:    true,
		Durable:     "mailer_test_rebind",
		RetryPolicy: pubsub.CriticalRetryPolicy(),
	}

	first := newTestPubSub(t, natsURL)
	err := first.Subscribe(context.Background(), topic, opts, func(context.Context, []byte) error {
		return nil
	})
	if err != nil {
		t.Fatalf("first Subscribe: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("close first pubsub: %v", err)
	}

	second := newTestPubSub(t, natsURL)
	defer func() {
		if err := second.Close(); err != nil {
			t.Fatalf("close second pubsub: %v", err)
		}
	}()
	defer cleanupTestStream(t, second, topic)
	err = second.Subscribe(context.Background(), topic, opts, func(context.Context, []byte) error {
		return nil
	})
	if err != nil {
		t.Fatalf("second Subscribe: %v", err)
	}
}

func newTestPubSub(t *testing.T, natsURL string) *NATSPubSub {
	t.Helper()

	ps, err := NewNATSPubSub(natsURL)
	if err != nil {
		t.Fatalf("NewNATSPubSub: %v", err)
	}
	natsPubSub, ok := ps.(*NATSPubSub)
	if !ok {
		t.Fatalf("NewNATSPubSub returned %T, want *NATSPubSub", ps)
	}
	return natsPubSub
}

func cleanupTestStream(t *testing.T, ps *NATSPubSub, topic topics.Topic) {
	t.Helper()

	err := ps.js.DeleteStream(streamName(topic))
	if err != nil {
		t.Logf("delete test stream: %v", err)
	}
}
