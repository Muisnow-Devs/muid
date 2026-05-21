package account

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"entgo.io/ent/dialect"
	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"sanzi.io/muid/internal/authn/ent"
	"sanzi.io/muid/internal/authn/ent/enttest"
)

func openPasskeyTestDB(t *testing.T) *ent.Client {
	t.Helper()
	dsn := fmt.Sprintf(
		"file:%s?mode=memory&cache=shared&_fk=1",
		strings.ReplaceAll(t.Name(), "/", "_"),
	)
	return enttest.Open(t, dialect.SQLite, dsn)
}

func TestPasskeyUsageUpdate_setsLastUsedAndCounter(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := openPasskeyTestDB(t)
	userID := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
	err := db.UserRef.Create().
		SetID(userID).
		SetEmail("user@example.com").
		Exec(ctx)
	if err != nil {
		t.Fatalf("seed user ref: %v", err)
	}

	accounts := New(&Store{DB: db}, nil)
	credentialID := []byte("credential-id")
	err = accounts.Passkey.LinkPasskey(ctx, LinkPasskeyConfig{
		UserId:         userID,
		CredentialID:   credentialID,
		PublicKey:      []byte("public-key"),
		RpID:           "localhost",
		DeviceType:     "multi_device",
		Name:           "Passkey",
		BackupEligible: true,
		BackupState:    false,
		SignCount:      1,
	})
	if err != nil {
		t.Fatalf("link passkey: %v", err)
	}

	lastUsed := time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC)
	err = accounts.Passkey.UpdatePasskeyUsage(ctx, UpdatePasskeyUsageConfig{
		CredentialID: credentialID,
		BackupState:  true,
		SignCount:    7,
		LastUsedAt:   lastUsed,
	})
	if err != nil {
		t.Fatalf("update usage: %v", err)
	}

	row, err := db.UserPasskey.Query().Only(ctx)
	if err != nil {
		t.Fatalf("load passkey: %v", err)
	}
	if !row.LastUsedAt.Equal(lastUsed) {
		t.Fatalf("last_used_at: got %s want %s", row.LastUsedAt, lastUsed)
	}
	if row.SignCount != 7 || !row.BackupState {
		t.Fatalf("usage fields: sign_count=%d backup_state=%v", row.SignCount, row.BackupState)
	}
}
