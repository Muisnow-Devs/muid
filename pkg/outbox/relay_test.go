package outbox

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"sanzi.io/muid/pkg/shared/pubsub"
	"sanzi.io/muid/pkg/shared/topics"
)

type fakeStore struct {
	mu sync.Mutex

	records       []Record
	claimErr      error
	markErr       error
	rescheduleErr error
	claims        int
	marked        []markedRecord
	rescheduled   []rescheduledRecord
}

type markedRecord struct {
	eventID     uuid.UUID
	leaseID     uuid.UUID
	publishedAt time.Time
}

type rescheduledRecord struct {
	eventID       uuid.UUID
	leaseID       uuid.UUID
	nextAttemptAt time.Time
	lastError     string
}

func (s *fakeStore) Claim(context.Context, time.Time, time.Duration) (Record, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.claims++
	if s.claimErr != nil {
		return Record{}, false, s.claimErr
	}
	if len(s.records) == 0 {
		return Record{}, false, nil
	}
	record := s.records[0]
	s.records = s.records[1:]
	return record, true, nil
}

func (s *fakeStore) MarkPublished(
	_ context.Context,
	eventID, leaseID uuid.UUID,
	publishedAt time.Time,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.marked = append(s.marked, markedRecord{eventID, leaseID, publishedAt})
	return s.markErr
}

func (s *fakeStore) Reschedule(
	_ context.Context,
	eventID, leaseID uuid.UUID,
	nextAttemptAt time.Time,
	lastError string,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rescheduled = append(s.rescheduled, rescheduledRecord{
		eventID: eventID, leaseID: leaseID, nextAttemptAt: nextAttemptAt, lastError: lastError,
	})
	return s.rescheduleErr
}

type fakePublisher struct {
	mu sync.Mutex

	err       error
	published []publishedRecord
}

type publishedRecord struct {
	topic   topics.Topic
	payload []byte
	opts    pubsub.PublishOptions
}

type blockingPublisher struct {
	started chan struct{}
}

func (p *blockingPublisher) PublishWithContext(
	ctx context.Context,
	_ topics.Topic,
	_ []byte,
	_ pubsub.PublishOptions,
) error {
	close(p.started)
	<-ctx.Done()
	return ctx.Err()
}

func (p *fakePublisher) PublishWithContext(
	_ context.Context,
	topic topics.Topic,
	message []byte,
	opts pubsub.PublishOptions,
) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.published = append(p.published, publishedRecord{topic, message, opts})
	return p.err
}

func TestNewRelayDefaultsAndValidation(t *testing.T) {
	t.Parallel()

	store := &fakeStore{}
	publisher := &fakePublisher{}
	relay, err := NewRelay(store, publisher, Config{})
	if err != nil {
		t.Fatalf("NewRelay: %v", err)
	}
	if relay.cfg.PollInterval != time.Second || relay.cfg.LeaseDuration != 30*time.Second ||
		relay.cfg.PublishTimeout != 10*time.Second || relay.cfg.RetryDelay != 10*time.Second ||
		relay.cfg.MaxPerPoll != 32 {
		t.Fatalf("defaults = %+v", relay.cfg)
	}

	tests := []struct {
		name      string
		store     Store
		publisher Publisher
		cfg       Config
	}{
		{name: "nil store", publisher: publisher},
		{name: "nil publisher", store: store},
		{name: "negative poll interval", store: store, publisher: publisher, cfg: Config{PollInterval: -time.Second}},
		{name: "publish timeout equals lease", store: store, publisher: publisher, cfg: Config{LeaseDuration: time.Second, PublishTimeout: time.Second}},
		{name: "retry cap below delay", store: store, publisher: publisher, cfg: Config{RetryDelay: time.Minute, RetryCap: time.Second}},
		{name: "retry horizon exceeded", store: store, publisher: publisher, cfg: Config{LeaseDuration: time.Minute, PublishTimeout: time.Second, RetryDelay: time.Second, RetryCap: pubsub.ReliableDeliveryHorizon}},
		{name: "lease horizon exceeded", store: store, publisher: publisher, cfg: Config{LeaseDuration: pubsub.ReliableDeliveryHorizon, PublishTimeout: time.Second}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := NewRelay(tc.store, tc.publisher, tc.cfg)
			if !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("NewRelay error = %v, want ErrInvalidConfig", err)
			}
		})
	}
}

func TestNewRelayAcceptsTransportHorizonBoundaries(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		cfg  Config
	}{
		{
			name: "retry cap plus publish timeout",
			cfg: Config{
				LeaseDuration:  time.Minute,
				PublishTimeout: time.Second,
				RetryDelay:     time.Second,
				RetryCap:       pubsub.ReliableDeliveryHorizon - time.Second,
			},
		},
		{
			name: "lease duration plus publish timeout",
			cfg: Config{
				LeaseDuration:  pubsub.ReliableDeliveryHorizon - time.Second,
				PublishTimeout: time.Second,
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := NewRelay(&fakeStore{}, &fakePublisher{}, tc.cfg)
			if err != nil {
				t.Fatalf("NewRelay: %v", err)
			}
		})
	}
}

func TestRelayDrainPublishesAndMarks(t *testing.T) {
	t.Parallel()

	record := testRecord(1)
	store := &fakeStore{records: []Record{record}}
	publisher := &fakePublisher{}
	relay := newTestRelay(t, store, publisher, Config{MaxPerPoll: 1})

	relay.drain(context.Background())

	if len(publisher.published) != 1 {
		t.Fatalf("publishes = %d, want 1", len(publisher.published))
	}
	published := publisher.published[0]
	if published.topic != record.Subject || string(published.payload) != string(record.Payload) {
		t.Fatalf("published record = %+v, want subject %q and payload %q", published, record.Subject, record.Payload)
	}
	if !published.opts.Reliable || published.opts.MessageID != record.ID.String() {
		t.Fatalf("publish options = %+v, want reliable message id %q", published.opts, record.ID)
	}
	if len(store.marked) != 1 || store.marked[0].eventID != record.ID || store.marked[0].leaseID != record.LeaseID {
		t.Fatalf("marked records = %+v", store.marked)
	}
	if len(store.rescheduled) != 0 {
		t.Fatalf("rescheduled records = %+v, want none", store.rescheduled)
	}
}

func TestRelayDrainReschedulesFailedPublishWithCappedBackoff(t *testing.T) {
	t.Parallel()

	record := testRecord(4)
	store := &fakeStore{records: []Record{record}}
	publisher := &fakePublisher{err: errors.New(strings.Repeat("x", maxLastErrorLength+1))}
	relay := newTestRelay(t, store, publisher, Config{
		RetryDelay: time.Second,
		RetryCap:   5 * time.Second,
		MaxPerPoll: 1,
	})
	before := time.Now()
	relay.drain(context.Background())

	if len(store.marked) != 0 {
		t.Fatalf("marked records = %+v, want none", store.marked)
	}
	if len(store.rescheduled) != 1 {
		t.Fatalf("rescheduled records = %d, want 1", len(store.rescheduled))
	}
	rescheduled := store.rescheduled[0]
	if rescheduled.eventID != record.ID || rescheduled.leaseID != record.LeaseID {
		t.Fatalf("rescheduled record = %+v", rescheduled)
	}
	if got := len(rescheduled.lastError); got != maxLastErrorLength {
		t.Fatalf("last error length = %d, want %d", got, maxLastErrorLength)
	}
	if delay := rescheduled.nextAttemptAt.Sub(before); delay < 5*time.Second || delay > 6*time.Second {
		t.Fatalf("retry delay = %v, want capped 5s", delay)
	}
}

func TestRelayDrainTruncatesLastErrorOnUTF8Boundary(t *testing.T) {
	t.Parallel()

	store := &fakeStore{records: []Record{testRecord(1)}}
	publisher := &fakePublisher{err: errors.New(strings.Repeat("€", 683))}
	relay := newTestRelay(t, store, publisher, Config{MaxPerPoll: 1})

	relay.drain(context.Background())

	if len(store.rescheduled) != 1 {
		t.Fatalf("rescheduled records = %d, want 1", len(store.rescheduled))
	}
	lastError := store.rescheduled[0].lastError
	if len(lastError) > maxLastErrorLength {
		t.Fatalf("last error length = %d, want at most %d", len(lastError), maxLastErrorLength)
	}
	if !utf8.ValidString(lastError) {
		t.Fatalf("last error is not valid UTF-8: %q", lastError)
	}
}

func TestRelayDrainLeavesLeaseAfterMarkFailure(t *testing.T) {
	t.Parallel()

	record := testRecord(1)
	store := &fakeStore{records: []Record{record}, markErr: errors.New("lease lost")}
	publisher := &fakePublisher{}
	relay := newTestRelay(t, store, publisher, Config{MaxPerPoll: 1})

	relay.drain(context.Background())

	if len(store.marked) != 1 {
		t.Fatalf("marked records = %d, want 1", len(store.marked))
	}
	if len(store.rescheduled) != 0 {
		t.Fatalf("rescheduled records = %+v, want none", store.rescheduled)
	}
}

func TestRelayDrainHonorsMaxPerPoll(t *testing.T) {
	t.Parallel()

	store := &fakeStore{records: []Record{testRecord(1), testRecord(1), testRecord(1)}}
	publisher := &fakePublisher{}
	relay := newTestRelay(t, store, publisher, Config{MaxPerPoll: 2})

	relay.drain(context.Background())

	if len(publisher.published) != 2 {
		t.Fatalf("publishes = %d, want 2", len(publisher.published))
	}
	if len(store.records) != 1 {
		t.Fatalf("remaining records = %d, want 1", len(store.records))
	}
}

func TestRelayStartIsSingleAndCloseWaits(t *testing.T) {
	t.Parallel()

	store := &fakeStore{}
	publisher := &fakePublisher{}
	relay := newTestRelay(t, store, publisher, Config{PollInterval: time.Hour})

	if err := relay.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := relay.Start(context.Background()); !errors.Is(err, ErrAlreadyStarted) {
		t.Fatalf("second Start error = %v, want ErrAlreadyStarted", err)
	}
	if err := relay.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := relay.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestRelayCloseCancelsBlockingPublish(t *testing.T) {
	t.Parallel()

	store := &fakeStore{records: []Record{testRecord(1)}}
	publisher := &blockingPublisher{started: make(chan struct{})}
	relay := newTestRelay(t, store, publisher, Config{PollInterval: time.Hour})
	if err := relay.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	select {
	case <-publisher.started:
	case <-time.After(time.Second):
		t.Fatal("publisher did not start")
	}

	done := make(chan error, 1)
	go func() { done <- relay.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not return after canceling publish")
	}
}

func newTestRelay(t *testing.T, store Store, publisher Publisher, cfg Config) *Relay {
	t.Helper()

	relay, err := NewRelay(store, publisher, cfg)
	if err != nil {
		t.Fatalf("NewRelay: %v", err)
	}
	return relay
}

func testRecord(attemptCount int) Record {
	return Record{
		ID:           uuid.New(),
		LeaseID:      uuid.New(),
		Subject:      topics.TopicSendOTP,
		Payload:      []byte("safe payload"),
		AttemptCount: attemptCount,
		CreatedAt:    time.Now(),
	}
}
