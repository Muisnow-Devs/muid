package postgresoutbox

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"sanzi.io/muid/pkg/outbox"
	"sanzi.io/muid/pkg/shared/topics"
	"sanzi.io/muid/pkg/sqldb"
)

func TestStorePostgresLeaseLifecycle(t *testing.T) {
	dsn := os.Getenv("MUID_POSTGRES_TEST_URL")
	if dsn == "" {
		t.Skip("MUID_POSTGRES_TEST_URL is not set")
	}

	ctx := context.Background()
	db, err := sqldb.OpenPostgres(ctx, dsn)
	if err != nil {
		t.Fatalf("open PostgreSQL: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close PostgreSQL: %v", err)
		}
	})
	storeOne, err := NewStore(db)
	if err != nil {
		t.Fatalf("NewStore first: %v", err)
	}
	storeTwo, err := NewStore(db)
	if err != nil {
		t.Fatalf("NewStore second: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	ids := []uuid.UUID{uuid.New(), uuid.New(), uuid.New(), uuid.New()}
	for index, id := range ids {
		insertOutboxEvent(t, db, id, now.Add(time.Duration(index)*time.Second))
	}
	t.Cleanup(func() {
		for _, id := range ids {
			if _, err := db.ExecContext(ctx, "DELETE FROM outbox_events WHERE id = $1", id); err != nil {
				t.Errorf("delete outbox event %s: %v", id, err)
			}
		}
	})

	claims := make(chan claimResult, 2)
	var waitGroup sync.WaitGroup
	for _, store := range []*Store{storeOne, storeTwo} {
		waitGroup.Add(1)
		go func(store *Store) {
			defer waitGroup.Done()
			record, ok, err := store.Claim(ctx, now.Add(10*time.Second), time.Second)
			claims <- claimResult{record: record, ok: ok, err: err}
		}(store)
	}
	waitGroup.Wait()
	close(claims)

	var claimed []claimResult
	for claim := range claims {
		if claim.err != nil || !claim.ok {
			t.Fatalf("concurrent Claim() = (%+v, %t, %v), want an event", claim.record, claim.ok, claim.err)
		}
		claimed = append(claimed, claim)
	}
	if len(claimed) != 2 || (claimed[0].record.ID == claimed[1].record.ID) {
		t.Fatalf("concurrent claims = %+v, want two distinct events", claimed)
	}
	if !containsClaimedID(claimed, ids[0]) || !containsClaimedID(claimed, ids[1]) {
		t.Fatalf("concurrent claim IDs = (%s, %s), want the first two due events", claimed[0].record.ID, claimed[1].record.ID)
	}
	first, second := claimed[0].record, claimed[1].record

	if err := storeOne.MarkPublished(ctx, first.ID, first.LeaseID, now.Add(11*time.Second)); err != nil {
		t.Fatalf("MarkPublished(): %v", err)
	}
	if err := storeTwo.Reschedule(ctx, second.ID, second.LeaseID, now.Add(30*time.Second), "temporary failure"); err != nil {
		t.Fatalf("Reschedule(): %v", err)
	}
	if err := storeOne.Reschedule(ctx, second.ID, second.LeaseID, now.Add(30*time.Second), "stale lease"); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("stale Reschedule() error = %v, want ErrLeaseLost", err)
	}

	expiring, ok, err := storeOne.Claim(ctx, now.Add(10*time.Second), time.Second)
	if err != nil || !ok || expiring.ID != ids[2] {
		t.Fatalf("expiring Claim() = (%+v, %t, %v), want %s", expiring, ok, err, ids[2])
	}
	reclaimed, ok, err := storeTwo.Claim(ctx, now.Add(12*time.Second), time.Second)
	if err != nil || !ok || reclaimed.ID != ids[2] {
		t.Fatalf("reclaimed Claim() = (%+v, %t, %v), want %s", reclaimed, ok, err, ids[2])
	}
	if reclaimed.LeaseID == expiring.LeaseID || reclaimed.AttemptCount != expiring.AttemptCount+1 {
		t.Fatalf("reclaimed record = %+v, want a new lease and incremented attempt count", reclaimed)
	}
	remaining, ok, err := storeOne.Claim(ctx, now.Add(14*time.Second), time.Second)
	if err != nil || !ok || remaining.ID != ids[3] {
		t.Fatalf("claim after publish = (%+v, %t, %v), want %s and never the published event", remaining, ok, err, ids[3])
	}
}

type claimResult struct {
	record outbox.Record
	ok     bool
	err    error
}

func containsClaimedID(claims []claimResult, id uuid.UUID) bool {
	for _, claim := range claims {
		if claim.record.ID == id {
			return true
		}
	}
	return false
}

func insertOutboxEvent(t *testing.T, db *sql.DB, id uuid.UUID, nextAttemptAt time.Time) {
	t.Helper()
	_, err := db.ExecContext(context.Background(), `
INSERT INTO outbox_events (id, subject, payload, attempt_count, created_at, next_attempt_at)
VALUES ($1, $2, $3, 0, $4, $5)`, id, topics.Topic("test.outbox"), []byte("payload"), nextAttemptAt, nextAttemptAt)
	if err != nil {
		t.Fatalf("insert outbox event: %v", err)
	}
}
