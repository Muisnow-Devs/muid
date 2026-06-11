package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"sanzi.io/muid/infra/mocked"
)

func TestCodeStoreSingleUse(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	codes := NewKVCodeStore(mocked.NewMockKVStore())
	record := CodeRecord{
		ClientRefID:         uuid.New(),
		ClientID:            "client-abc",
		UserID:              uuid.New(),
		SessionID:           uuid.New(),
		RedirectURI:         "https://app.test/cb",
		Scopes:              []string{"openid", "profile"},
		Nonce:               "nonce-1",
		CodeChallenge:       "challenge",
		CodeChallengeMethod: "S256",
		AuthTime:            time.Now().Unix(),
	}

	code, err := codes.Create(ctx, record)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if code == "" {
		t.Fatal("Create returned empty code")
	}

	got, err := codes.Consume(ctx, code)
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if got.UserID != record.UserID || got.RedirectURI != record.RedirectURI ||
		got.CodeChallenge != record.CodeChallenge {
		t.Fatalf("Consume record = %+v, want fields from %+v", got, record)
	}

	_, err = codes.Consume(ctx, code)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("second Consume err = %v, want ErrNotFound", err)
	}
}

func TestCodeStoreUnknownCode(t *testing.T) {
	t.Parallel()

	codes := NewKVCodeStore(mocked.NewMockKVStore())
	_, err := codes.Consume(context.Background(), "missing")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Consume err = %v, want ErrNotFound", err)
	}
}

func TestPendingStoreConsumeOnce(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	pendings := NewKVPendingStore(mocked.NewMockKVStore())
	pending := PendingAuthorization{
		ClientRefID: uuid.New(),
		ClientID:    "client-abc",
		UserID:      uuid.New(),
		RedirectURI: "https://app.test/cb",
		State:       "state-1",
		Scopes:      []string{"openid"},
	}

	id, err := pendings.Create(ctx, pending)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := pendings.Consume(ctx, id)
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if got.ID != id || got.State != "state-1" || got.UserID != pending.UserID {
		t.Fatalf("Consume = %+v, want id %s state state-1", got, id)
	}

	_, err = pendings.Consume(ctx, id)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("second Consume err = %v, want ErrNotFound", err)
	}
}

func TestDeviceStoreLifecycle(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	devices := NewKVDeviceStore(mocked.NewMockKVStore())
	userID := uuid.New()

	deviceCode, userCode, err := devices.Create(ctx, DeviceRecord{
		ClientRefID:     uuid.New(),
		ClientID:        "client-abc",
		Scopes:          []string{"openid"},
		IntervalSeconds: 5,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if len(userCode) != userCodeLength {
		t.Fatalf("user code %q length = %d, want %d", userCode, len(userCode), userCodeLength)
	}
	for _, r := range userCode {
		if !strings.ContainsRune(userCodeAlphabet, r) {
			t.Fatalf("user code %q contains %q outside alphabet", userCode, r)
		}
	}

	gotDeviceCode, record, err := devices.GetByUserCode(ctx, userCode)
	if err != nil {
		t.Fatalf("GetByUserCode: %v", err)
	}
	if gotDeviceCode != deviceCode || record.Status != DeviceStatusPending {
		t.Fatalf(
			"GetByUserCode = (%q, %q), want (%q, pending)",
			gotDeviceCode, record.Status, deviceCode,
		)
	}

	// Pending records cannot be claimed.
	pending, claimed, err := devices.ConsumeApproved(ctx, deviceCode)
	if err != nil {
		t.Fatalf("ConsumeApproved pending: %v", err)
	}
	if claimed || pending.Status != DeviceStatusPending {
		t.Fatalf("ConsumeApproved pending = (claimed %v, %q), want (false, pending)",
			claimed, pending.Status)
	}

	record.Status = DeviceStatusApproved
	record.UserID = userID
	err = devices.Update(ctx, deviceCode, record)
	if err != nil {
		t.Fatalf("Update: %v", err)
	}

	approved, claimed, err := devices.ConsumeApproved(ctx, deviceCode)
	if err != nil {
		t.Fatalf("ConsumeApproved: %v", err)
	}
	if !claimed || approved.UserID != userID {
		t.Fatalf("ConsumeApproved = (claimed %v, user %s), want (true, %s)",
			claimed, approved.UserID, userID)
	}

	// Claimed exactly once; the user-code lookup is gone too.
	_, _, err = devices.ConsumeApproved(ctx, deviceCode)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("second ConsumeApproved err = %v, want ErrNotFound", err)
	}
	_, _, err = devices.GetByUserCode(ctx, userCode)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetByUserCode after consume err = %v, want ErrNotFound", err)
	}
}

func TestDeviceStoreAllowPoll(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	devices := NewKVDeviceStore(mocked.NewMockKVStore())

	allowed, err := devices.AllowPoll(ctx, "device-1", time.Minute)
	if err != nil {
		t.Fatalf("AllowPoll first: %v", err)
	}
	if !allowed {
		t.Fatal("AllowPoll first = false, want true")
	}

	allowed, err = devices.AllowPoll(ctx, "device-1", time.Minute)
	if err != nil {
		t.Fatalf("AllowPoll second: %v", err)
	}
	if allowed {
		t.Fatal("AllowPoll second = true, want false (slow_down)")
	}

	// A different device code is throttled independently.
	allowed, err = devices.AllowPoll(ctx, "device-2", time.Minute)
	if err != nil {
		t.Fatalf("AllowPoll other: %v", err)
	}
	if !allowed {
		t.Fatal("AllowPoll other = false, want true")
	}
}
