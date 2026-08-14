package ent_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"

	"sanzi.io/muid/internal/authn/ent"
	"sanzi.io/muid/internal/authn/ent/enttest"
	"sanzi.io/muid/internal/authn/ent/userref"
)

func TestUserRefStatusDefaultAndRoundTrip(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := enttest.Open(t, "sqlite3", "file:userrefstatusdefault?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() { db.Close() })

	created, err := db.UserRef.Create().SetID(uuid.New()).Save(ctx)
	if err != nil {
		t.Fatalf("create user ref: %v", err)
	}
	if created.Status != userref.StatusActive {
		t.Errorf("created status = %q, want %q", created.Status, userref.StatusActive)
	}

	updated, err := created.Update().SetStatus(userref.StatusPendingDeletion).Save(ctx)
	if err != nil {
		t.Fatalf("update user ref status: %v", err)
	}
	if updated.Status != userref.StatusPendingDeletion {
		t.Errorf("updated status = %q, want %q", updated.Status, userref.StatusPendingDeletion)
	}

	found, err := db.UserRef.Get(ctx, created.ID)
	if err != nil {
		t.Fatalf("query user ref: %v", err)
	}
	if found.Status != userref.StatusPendingDeletion {
		t.Errorf("persisted status = %q, want %q", found.Status, userref.StatusPendingDeletion)
	}
}

func TestUserRefStatusMigrationBackfillsExistingRows(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	const dataSourceName = "file:userrefstatusbackfill?mode=memory&cache=shared&_fk=1"
	legacyDB, err := sql.Open("sqlite3", dataSourceName)
	if err != nil {
		t.Fatalf("open legacy database: %v", err)
	}
	t.Cleanup(func() { legacyDB.Close() })

	_, err = legacyDB.ExecContext(ctx, `
		CREATE TABLE user_refs (
			id uuid NOT NULL PRIMARY KEY,
			last_login_at datetime NULL,
			created_at datetime NOT NULL,
			updated_at datetime NOT NULL
		)
	`)
	if err != nil {
		t.Fatalf("create legacy user_refs table: %v", err)
	}

	userID := uuid.New()
	_, err = legacyDB.ExecContext(
		ctx,
		"INSERT INTO user_refs (id, created_at, updated_at) VALUES (?, ?, ?)",
		userID.String(),
		time.Now(),
		time.Now(),
	)
	if err != nil {
		t.Fatalf("insert legacy user ref: %v", err)
	}

	db, err := ent.Open("sqlite3", dataSourceName)
	if err != nil {
		t.Fatalf("open Ent client: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	err = db.Schema.Create(ctx)
	if err != nil {
		t.Fatalf("migrate user_refs: %v", err)
	}

	backfilled, err := db.UserRef.Get(ctx, userID)
	if err != nil {
		t.Fatalf("query backfilled user ref: %v", err)
	}
	if backfilled.Status != userref.StatusActive {
		t.Errorf("backfilled status = %q, want %q", backfilled.Status, userref.StatusActive)
	}
}
