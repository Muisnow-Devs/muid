package postgresoutbox

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
)

const testDriverName = "postgresoutbox_test"

var (
	testDriverOnce sync.Once
	testSQLDriver  = &scriptedDriver{}
)

func TestNewStore(t *testing.T) {
	store, err := NewStore(nil)
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("NewStore(nil) error = %v, want ErrInvalidConfig", err)
	}
	if store != nil {
		t.Fatal("NewStore(nil) returned a store")
	}
}

func TestStore_Claim(t *testing.T) {
	now := time.Date(2026, time.August, 15, 8, 0, 0, 0, time.UTC)
	eventID := uuid.New()
	leaseID := uuid.New()
	script := &sqlScript{rows: &scriptedRows{
		columns: []string{"id", "subject", "payload", "attempt_count", "created_at", "lease_id"},
		values:  [][]driver.Value{{eventID.String(), "authn.login", []byte("payload"), int64(2), now.Add(-time.Minute), leaseID.String()}},
	}}
	store := newTestStore(t, script)

	record, ok, err := store.Claim(context.Background(), now, 30*time.Second)
	if err != nil {
		t.Fatalf("Claim() error = %v", err)
	}
	if !ok {
		t.Fatal("Claim() ok = false, want true")
	}
	if record.ID != eventID || record.LeaseID != leaseID || record.Subject != "authn.login" || record.AttemptCount != 2 {
		t.Fatalf("Claim() record = %+v, want claimed row", record)
	}
	if !strings.Contains(script.query, "WITH candidate AS") ||
		!strings.Contains(script.query, "FOR UPDATE SKIP LOCKED") ||
		!strings.Contains(script.query, "ORDER BY next_attempt_at, created_at, id") ||
		!strings.Contains(script.query, "UPDATE outbox_events AS events") {
		t.Fatalf("Claim() query does not use the required atomic CTE: %s", script.query)
	}
	if len(script.args) != 3 || script.args[0].Value != now || script.args[1].Value == uuid.Nil || script.args[2].Value != now.Add(30*time.Second) {
		t.Fatalf("Claim() args = %#v, want now, non-nil lease ID, and lease expiration", script.args)
	}
}

func TestStore_ClaimNoRecord(t *testing.T) {
	store := newTestStore(t, &sqlScript{rows: &scriptedRows{columns: []string{"id"}}})

	record, ok, err := store.Claim(context.Background(), time.Now().UTC(), time.Second)
	if err != nil {
		t.Fatalf("Claim() error = %v", err)
	}
	if ok || record.ID != uuid.Nil {
		t.Fatalf("Claim() = (%+v, %t), want no record", record, ok)
	}
}

func TestStore_LeaseProtectedUpdates(t *testing.T) {
	now := time.Date(2026, time.August, 15, 8, 0, 0, 0, time.UTC)
	eventID := uuid.New()
	leaseID := uuid.New()

	t.Run("mark published", func(t *testing.T) {
		script := &sqlScript{result: driver.RowsAffected(1)}
		store := newTestStore(t, script)

		err := store.MarkPublished(context.Background(), eventID, leaseID, now)
		if err != nil {
			t.Fatalf("MarkPublished() error = %v", err)
		}
		if !strings.Contains(script.query, "published_at IS NULL") ||
			!strings.Contains(script.query, "lease_id = NULL") ||
			!strings.Contains(script.query, "last_error = NULL") {
			t.Fatalf("MarkPublished() query = %s, want lease-protected cleanup", script.query)
		}
	})

	t.Run("reschedule truncates at UTF-8 boundary", func(t *testing.T) {
		script := &sqlScript{result: driver.RowsAffected(1)}
		store := newTestStore(t, script)
		lastError := strings.Repeat("a", maxLastErrorLength-1) + "界" + "ignored"

		err := store.Reschedule(context.Background(), eventID, leaseID, now, lastError)
		if err != nil {
			t.Fatalf("Reschedule() error = %v", err)
		}
		if !strings.Contains(script.query, "published_at IS NULL") ||
			!strings.Contains(script.query, "lease_id = NULL") ||
			!strings.Contains(script.query, "lease_until = NULL") {
			t.Fatalf("Reschedule() query = %s, want lease-protected release", script.query)
		}
		got, ok := script.args[3].Value.(string)
		if !ok || len(got) > maxLastErrorLength || !utf8.ValidString(got) {
			t.Fatalf("Reschedule() last error = %q, want valid UTF-8 capped at %d bytes", got, maxLastErrorLength)
		}
	})

	t.Run("stale lease", func(t *testing.T) {
		store := newTestStore(t, &sqlScript{result: driver.RowsAffected(0)})

		err := store.MarkPublished(context.Background(), eventID, leaseID, now)
		if !errors.Is(err, ErrLeaseLost) {
			t.Fatalf("MarkPublished() error = %v, want ErrLeaseLost", err)
		}
	})
}

func TestStore_RejectsInvalidInputs(t *testing.T) {
	store := newTestStore(t, &sqlScript{})
	now := time.Now().UTC()
	id := uuid.New()

	tests := []struct {
		name string
		call func() error
	}{
		{
			name: "claim zero time",
			call: func() error {
				_, _, err := store.Claim(context.Background(), time.Time{}, time.Second)
				return err
			},
		},
		{
			name: "claim zero lease duration",
			call: func() error {
				_, _, err := store.Claim(context.Background(), now, 0)
				return err
			},
		},
		{
			name: "mark nil event ID",
			call: func() error {
				return store.MarkPublished(context.Background(), uuid.Nil, id, now)
			},
		},
		{
			name: "reschedule zero next attempt",
			call: func() error {
				return store.Reschedule(context.Background(), id, id, time.Time{}, "failed")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.call(); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("error = %v, want ErrInvalidConfig", err)
			}
		})
	}
}

func newTestStore(t *testing.T, script *sqlScript) *Store {
	t.Helper()
	testDriverOnce.Do(func() {
		sql.Register(testDriverName, testSQLDriver)
	})
	testSQLDriver.setScript(script)
	db, err := sql.Open(testDriverName, "")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("db.Close: %v", err)
		}
	})
	store, err := NewStore(db)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return store
}

type scriptedDriver struct {
	mu     sync.Mutex
	script *sqlScript
}

func (d *scriptedDriver) Open(string) (driver.Conn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return &scriptedConn{script: d.script}, nil
}

func (d *scriptedDriver) setScript(script *sqlScript) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.script = script
}

type scriptedConn struct {
	script *sqlScript
}

func (c *scriptedConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("not implemented")
}
func (c *scriptedConn) Close() error              { return nil }
func (c *scriptedConn) Begin() (driver.Tx, error) { return nil, errors.New("not implemented") }

func (c *scriptedConn) QueryContext(
	_ context.Context,
	query string,
	args []driver.NamedValue,
) (driver.Rows, error) {
	c.script.query = query
	c.script.args = args
	if c.script.queryErr != nil {
		return nil, c.script.queryErr
	}
	return c.script.rows, nil
}

func (c *scriptedConn) ExecContext(
	_ context.Context,
	query string,
	args []driver.NamedValue,
) (driver.Result, error) {
	c.script.query = query
	c.script.args = args
	if c.script.execErr != nil {
		return nil, c.script.execErr
	}
	return c.script.result, nil
}

type sqlScript struct {
	rows     driver.Rows
	result   driver.Result
	queryErr error
	execErr  error
	query    string
	args     []driver.NamedValue
}

type scriptedRows struct {
	columns []string
	values  [][]driver.Value
	index   int
}

func (r *scriptedRows) Columns() []string { return r.columns }
func (r *scriptedRows) Close() error      { return nil }

func (r *scriptedRows) Next(dest []driver.Value) error {
	if r.index >= len(r.values) {
		return io.EOF
	}
	copy(dest, r.values[r.index])
	r.index++
	return nil
}
