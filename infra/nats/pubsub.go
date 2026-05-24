package nats

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"
	"unicode"

	natsio "github.com/nats-io/nats.go"
	"sanzi.io/muid/pkg/log"
	"sanzi.io/muid/pkg/shared"
	"sanzi.io/muid/pkg/shared/pubsub"
	"sanzi.io/muid/pkg/shared/topics"
)

type NATSPubSub struct {
	conn *natsio.Conn
	js   natsio.JetStreamContext
}

// NewNATSPubSub connects to NATS at natsURL and returns a [PubSub] client.
func NewNATSPubSub(natsURL string) (PubSub, error) {
	client, err := natsio.Connect(natsURL)
	if err != nil {
		return nil, err
	}

	js, err := client.JetStream()
	if err != nil {
		client.Close()
		return nil, err
	}

	return &NATSPubSub{conn: client, js: js}, nil
}

func (n *NATSPubSub) Publish(topic topics.Topic, message []byte) error {
	return n.PublishWithOptions(topic, message, pubsub.PublishOptions{})
}

func (n *NATSPubSub) PublishWithOptions(
	topic topics.Topic,
	message []byte,
	opts pubsub.PublishOptions,
) error {
	msg := &natsio.Msg{
		Subject: string(topic),
		Header:  natsio.Header{},
		Data:    message,
	}
	pubsub.EncodeRetryPolicyHeaders(msg.Header, opts.RetryPolicy)

	if !opts.Reliable {
		return n.conn.PublishMsg(msg)
	}

	_, err := n.ensureStream(topic)
	if err != nil {
		return err
	}
	_, err = n.js.PublishMsg(msg)
	return err
}

func (n *NATSPubSub) Subscribe(
	ctx context.Context,
	topic topics.Topic,
	opts pubsub.SubscribeOptions,
	handler func(ctx context.Context, message []byte) error,
) error {
	if opts.Reliable {
		return n.subscribeReliable(ctx, topic, opts, handler)
	}

	cb := func(msg *natsio.Msg) {
		workCtx, cancel := context.WithTimeout(ctx, pubsub.SubscribeTaskTimeout)
		defer cancel()

		ctx := log.With(workCtx, shared.UUIDV7().String())

		if err := handler(ctx, msg.Data); err != nil {
			log.LogUnexpected(
				ctx,
				"nats subscriber",
				err.Error(),
				slog.String("topic", string(topic)),
			)
		}
	}

	var err error
	if opts.QueueGroup != "" {
		_, err = n.conn.QueueSubscribe(string(topic), opts.QueueGroup, cb)
	} else {
		_, err = n.conn.Subscribe(string(topic), cb)
	}

	return err
}

func (n *NATSPubSub) subscribeReliable(
	ctx context.Context,
	topic topics.Topic,
	opts pubsub.SubscribeOptions,
	handler func(ctx context.Context, message []byte) error,
) error {
	stream, err := n.ensureStream(topic)
	if err != nil {
		return err
	}

	policy := opts.RetryPolicy.WithDefaults()
	subOpts := []natsio.SubOpt{
		natsio.ManualAck(),
		natsio.BindStream(stream),
		natsio.Durable(durableName(topic, opts)),
		natsio.MaxDeliver(policy.MaxAttempts),
	}
	backoff := policy.BackoffSchedule()
	if len(backoff) > 0 {
		subOpts = append(subOpts, natsio.BackOff(backoff))
	} else {
		subOpts = append(subOpts, natsio.AckWait(policy.MaxDelay))
	}

	cb := func(msg *natsio.Msg) {
		n.handleReliableMessage(ctx, topic, opts, msg, handler)
	}

	if opts.QueueGroup != "" {
		_, err = n.js.QueueSubscribe(string(topic), opts.QueueGroup, cb, subOpts...)
		return err
	}

	_, err = n.js.Subscribe(string(topic), cb, subOpts...)
	return err
}

func (n *NATSPubSub) handleReliableMessage(
	ctx context.Context,
	topic topics.Topic,
	opts pubsub.SubscribeOptions,
	msg *natsio.Msg,
	handler func(ctx context.Context, message []byte) error,
) {
	workCtx, cancel := context.WithTimeout(ctx, pubsub.SubscribeTaskTimeout)
	defer cancel()

	ctx = log.With(workCtx, shared.UUIDV7().String())
	err := handler(ctx, msg.Data)
	if err == nil {
		n.ackMessage(ctx, topic, msg)
		return
	}

	log.LogUnexpected(
		ctx,
		"nats subscriber",
		err.Error(),
		slog.String("topic", string(topic)),
	)
	ackErr := n.retryOrTerminate(ctx, topic, opts, msg, err)
	if ackErr != nil {
		log.LogUnexpected(
			ctx,
			"nats message ack",
			ackErr.Error(),
			slog.String("topic", string(topic)),
		)
	}
}

func (n *NATSPubSub) ackMessage(ctx context.Context, topic topics.Topic, msg *natsio.Msg) {
	err := msg.Ack()
	if err == nil {
		return
	}
	log.LogUnexpected(
		ctx,
		"nats message ack",
		err.Error(),
		slog.String("topic", string(topic)),
	)
}

func (n *NATSPubSub) retryOrTerminate(
	ctx context.Context,
	topic topics.Topic,
	opts pubsub.SubscribeOptions,
	msg *natsio.Msg,
	handlerErr error,
) error {
	if errors.Is(handlerErr, pubsub.ErrNonRetryable) {
		return msg.Term()
	}

	policy, _, err := pubsub.DecodeRetryPolicyHeaders(msg.Header)
	if err != nil {
		log.LogUnexpected(
			ctx,
			"nats retry policy",
			err.Error(),
			slog.String("topic", string(topic)),
		)
		policy = opts.RetryPolicy.WithDefaults()
	}
	if policy.MaxAttempts <= 1 {
		return msg.Term()
	}

	attempt := uint64(1)
	meta, err := msg.Metadata()
	if err == nil && meta.NumDelivered > 0 {
		attempt = meta.NumDelivered
	}
	if attempt >= uint64(policy.MaxAttempts) {
		return msg.Term()
	}

	return msg.NakWithDelay(policy.DelayForAttempt(attempt))
}

func (n *NATSPubSub) ensureStream(topic topics.Topic) (string, error) {
	subject := string(topic)
	foundStream, err := n.js.StreamNameBySubject(subject)
	if err == nil && foundStream != "" {
		return foundStream, nil
	}
	if err != nil &&
		!errors.Is(err, natsio.ErrStreamNotFound) &&
		!errors.Is(err, natsio.ErrNoMatchingStream) {
		return "", err
	}

	stream := streamName(topic)
	_, err = n.js.StreamInfo(stream)
	if err == nil {
		return stream, nil
	}
	if !errors.Is(err, natsio.ErrStreamNotFound) {
		return "", err
	}

	_, err = n.js.AddStream(&natsio.StreamConfig{
		Name:      stream,
		Subjects:  []string{subject},
		Retention: natsio.LimitsPolicy,
		Storage:   natsio.FileStorage,
		MaxAge:    7 * 24 * time.Hour,
	})
	if err != nil && !errors.Is(err, natsio.ErrStreamNameAlreadyInUse) {
		return "", err
	}
	return stream, nil
}

func streamName(topic topics.Topic) string {
	var b strings.Builder
	b.WriteString("MUID_")
	for _, r := range string(topic) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(unicode.ToUpper(r))
			continue
		}
		b.WriteRune('_')
	}
	return b.String()
}

func durableName(topic topics.Topic, opts pubsub.SubscribeOptions) string {
	if opts.Durable != "" {
		return opts.Durable
	}
	if opts.QueueGroup != "" {
		return streamName(topic) + "_" + strings.ToUpper(opts.QueueGroup)
	}
	return streamName(topic) + "_DURABLE"
}

func (n *NATSPubSub) Close() error {
	n.conn.Close()
	return nil
}
