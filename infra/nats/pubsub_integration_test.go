package nats

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	natsio "github.com/nats-io/nats.go"
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

func TestReliablePublishSetsMessageIDHeader(t *testing.T) {
	natsURL := os.Getenv("MUID_NATS_TEST_URL")
	if natsURL == "" {
		t.Skip("MUID_NATS_TEST_URL is not set")
	}

	topic := topics.Topic("test.outbox.message-id." + time.Now().UTC().Format("20060102150405.000000000"))
	messageID := "outbox-event-123"
	ps := newTestPubSub(t, natsURL)
	defer func() {
		if err := ps.Close(); err != nil {
			t.Fatalf("close pubsub: %v", err)
		}
	}()
	defer cleanupTestStream(t, ps, topic)

	err := ps.PublishWithOptions(topic, []byte("payload"), pubsub.PublishOptions{
		Reliable:  true,
		MessageID: messageID,
	})
	if err != nil {
		t.Fatalf("PublishWithOptions: %v", err)
	}

	msg, err := ps.js.GetMsg(streamName(topic), 1)
	if err != nil {
		t.Fatalf("GetMsg: %v", err)
	}
	if got := msg.Header.Get(natsio.MsgIdHdr); got != messageID {
		t.Fatalf("message id header = %q, want %q", got, messageID)
	}
}

func TestReliablePublishDeduplicatesMessageID(t *testing.T) {
	natsURL := os.Getenv("MUID_NATS_TEST_URL")
	if natsURL == "" {
		t.Skip("MUID_NATS_TEST_URL is not set")
	}

	topic := topics.Topic("test.outbox.deduplicate." + time.Now().UTC().Format("20060102150405.000000000"))
	ps := newTestPubSub(t, natsURL)
	defer func() {
		if err := ps.Close(); err != nil {
			t.Fatalf("close pubsub: %v", err)
		}
	}()
	defer cleanupTestStream(t, ps, topic)

	for _, messageID := range []string{"event-1", "event-1", "event-2"} {
		err := ps.PublishWithOptions(topic, []byte("payload"), pubsub.PublishOptions{
			Reliable:  true,
			MessageID: messageID,
		})
		if err != nil {
			t.Fatalf("PublishWithOptions(%q): %v", messageID, err)
		}
	}

	info, err := ps.js.StreamInfo(streamName(topic))
	if err != nil {
		t.Fatalf("StreamInfo: %v", err)
	}
	if info.Config.Duplicates < pubsub.ReliableDeliveryHorizon {
		t.Fatalf("duplicate window = %v, want at least %v", info.Config.Duplicates, pubsub.ReliableDeliveryHorizon)
	}
	if got := info.State.Msgs; got != 2 {
		t.Fatalf("stored messages = %d, want 2 after duplicate message ID", got)
	}
}

func TestReliablePublishExpiredDeadlineDoesNotProvisionStream(t *testing.T) {
	natsURL := os.Getenv("MUID_NATS_TEST_URL")
	if natsURL == "" {
		t.Skip("MUID_NATS_TEST_URL is not set")
	}

	topic := topics.Topic("test.outbox.expired." + time.Now().UTC().Format("20060102150405.000000000"))
	ps := newTestPubSub(t, natsURL)
	defer func() {
		if err := ps.Close(); err != nil {
			t.Fatalf("close pubsub: %v", err)
		}
	}()
	defer cleanupTestStream(t, ps, topic)

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	err := ps.PublishWithContext(ctx, topic, []byte("payload"), pubsub.PublishOptions{Reliable: true})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("PublishWithContext error = %v, want DeadlineExceeded", err)
	}
	_, err = ps.js.StreamInfo(streamName(topic))
	if !errors.Is(err, natsio.ErrStreamNotFound) {
		t.Fatalf("StreamInfo error = %v, want ErrStreamNotFound", err)
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
