package outbox

import (
	"context"
	"log/slog"
	"math"
	"sync"
	"time"
	"unicode/utf8"

	"sanzi.io/muid/pkg/log"
	"sanzi.io/muid/pkg/shared/pubsub"
)

const (
	defaultPollInterval   = time.Second
	defaultLeaseDuration  = 30 * time.Second
	defaultPublishTimeout = 10 * time.Second
	defaultRetryDelay     = 10 * time.Second
	defaultRetryCap       = 5 * time.Minute
	defaultMaxPerPoll     = 32
	maxLastErrorLength    = 2048
)

// Relay delivers claimed outbox records one at a time.
type Relay struct {
	store     Store
	publisher Publisher
	cfg       Config

	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
}

// NewRelay constructs a relay. Its worker is started by Start.
func NewRelay(store Store, publisher Publisher, cfg Config) (*Relay, error) {
	if store == nil || publisher == nil {
		return nil, ErrInvalidConfig
	}
	cfg = cfg.withDefaults()
	if !cfg.valid() {
		return nil, ErrInvalidConfig
	}
	return &Relay{store: store, publisher: publisher, cfg: cfg}, nil
}

// Start starts one relay worker that stops when ctx is cancelled or Close is called.
func (r *Relay) Start(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalidConfig
	}

	workerCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})

	r.mu.Lock()
	if r.cancel != nil {
		r.mu.Unlock()
		cancel()
		return ErrAlreadyStarted
	}
	r.cancel = cancel
	r.done = done
	r.mu.Unlock()

	go func() {
		defer close(done)
		r.run(workerCtx)
	}()
	return nil
}

// Close stops the relay worker and waits for it to exit. It is idempotent.
func (r *Relay) Close() error {
	r.mu.Lock()
	cancel := r.cancel
	done := r.done
	r.mu.Unlock()
	if cancel == nil {
		return nil
	}

	cancel()
	<-done
	return nil
}

func (r *Relay) run(ctx context.Context) {
	r.drain(ctx)

	ticker := time.NewTicker(r.cfg.PollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.drain(ctx)
		}
	}
}

func (r *Relay) drain(ctx context.Context) {
	for range r.cfg.MaxPerPoll {
		if ctx.Err() != nil {
			return
		}

		record, ok, err := r.store.Claim(ctx, time.Now(), r.cfg.LeaseDuration)
		if err != nil {
			log.LogUnexpected(ctx, "outbox claim", err.Error())
			return
		}
		if !ok {
			return
		}
		r.deliver(ctx, record)
	}
}

func (r *Relay) deliver(ctx context.Context, record Record) {
	publishCtx, cancel := context.WithTimeout(ctx, r.cfg.PublishTimeout)
	defer cancel()

	err := r.publisher.PublishWithContext(publishCtx, record.Subject, record.Payload, pubsub.PublishOptions{
		Reliable:  true,
		MessageID: record.ID.String(),
	})
	if err != nil {
		r.reschedule(ctx, record, err)
		return
	}

	err = r.store.MarkPublished(ctx, record.ID, record.LeaseID, time.Now())
	if err != nil {
		log.LogUnexpected(
			ctx,
			"outbox mark published",
			err.Error(),
			slog.String("event_id", record.ID.String()),
		)
	}
}

func (r *Relay) reschedule(ctx context.Context, record Record, cause error) {
	nextAttemptAt := time.Now().Add(r.retryDelay(record.AttemptCount))
	err := r.store.Reschedule(
		ctx,
		record.ID,
		record.LeaseID,
		nextAttemptAt,
		truncateLastError(cause.Error()),
	)
	if err == nil {
		return
	}
	log.LogUnexpected(
		ctx,
		"outbox reschedule",
		err.Error(),
		slog.String("event_id", record.ID.String()),
	)
}

func (r *Relay) retryDelay(attempt int) time.Duration {
	if attempt <= 1 {
		return r.cfg.RetryDelay
	}

	delay := float64(r.cfg.RetryDelay) * math.Pow(2, float64(attempt-1))
	if delay >= float64(r.cfg.RetryCap) || math.IsInf(delay, 0) {
		return r.cfg.RetryCap
	}
	return time.Duration(delay)
}

func (cfg Config) withDefaults() Config {
	if cfg.PollInterval == 0 {
		cfg.PollInterval = defaultPollInterval
	}
	if cfg.LeaseDuration == 0 {
		cfg.LeaseDuration = defaultLeaseDuration
	}
	if cfg.PublishTimeout == 0 {
		cfg.PublishTimeout = defaultPublishTimeout
	}
	if cfg.RetryDelay == 0 {
		cfg.RetryDelay = defaultRetryDelay
	}
	if cfg.RetryCap == 0 {
		cfg.RetryCap = defaultRetryCap
	}
	if cfg.MaxPerPoll == 0 {
		cfg.MaxPerPoll = defaultMaxPerPoll
	}
	return cfg
}

func (cfg Config) valid() bool {
	return cfg.PollInterval > 0 &&
		cfg.LeaseDuration > 0 &&
		cfg.PublishTimeout > 0 &&
		cfg.PublishTimeout < cfg.LeaseDuration &&
		cfg.RetryDelay > 0 &&
		cfg.RetryCap >= cfg.RetryDelay &&
		cfg.RetryCap+cfg.PublishTimeout <= pubsub.ReliableDeliveryHorizon &&
		cfg.LeaseDuration+cfg.PublishTimeout <= pubsub.ReliableDeliveryHorizon &&
		cfg.MaxPerPoll > 0
}

func truncateLastError(message string) string {
	if len(message) <= maxLastErrorLength {
		return message
	}
	limit := maxLastErrorLength
	for limit > 0 && !utf8.RuneStart(message[limit]) {
		limit--
	}
	return message[:limit]
}
