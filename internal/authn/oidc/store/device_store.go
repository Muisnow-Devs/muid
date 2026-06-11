package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"sanzi.io/muid/pkg/shared/kv"
	"sanzi.io/muid/pkg/shared/tracing"
)

// deviceTTL is the device-code validity window (RFC 8628 expires_in).
const deviceTTL = 15 * time.Minute

const (
	deviceKeyPrefix         = "muid:oidc:device:"
	deviceUserCodeKeyPrefix = "muid:oidc:device:user_code:"
	devicePollKeyPrefix     = "muid:oidc:device:poll:"
)

// userCodeCreateAttempts bounds retries on (unlikely) user-code collisions.
const userCodeCreateAttempts = 5

type DeviceStatus string

const (
	DeviceStatusPending  DeviceStatus = "pending"
	DeviceStatusApproved DeviceStatus = "approved"
	DeviceStatusDenied   DeviceStatus = "denied"
)

// DeviceRecord is the state of one RFC 8628 device authorization.
type DeviceRecord struct {
	ClientRefID uuid.UUID `json:"client_ref_id"`
	ClientID    string    `json:"client_id"`

	Scopes   []string     `json:"scopes,omitempty"`
	UserCode string       `json:"user_code"`
	Status   DeviceStatus `json:"status"`
	// UserID is set when the record transitions to approved.
	UserID uuid.UUID `json:"user_id,omitempty"`

	IntervalSeconds int64 `json:"interval_seconds"`
	CreatedAt       int64 `json:"created_at"`
	ExpiresAt       int64 `json:"expires_at"`
}

// KVDeviceStore stores device authorizations plus the user-code lookup and
// poll-throttle keys that accompany them.
type KVDeviceStore struct {
	client kv.AtomicKVStore
}

func NewKVDeviceStore(client kv.AtomicKVStore) *KVDeviceStore {
	return &KVDeviceStore{client: client}
}

// TTL returns the device-code validity window (expires_in).
func (s *KVDeviceStore) TTL() time.Duration {
	return deviceTTL
}

// Create starts a device authorization and returns (device_code, user_code).
func (s *KVDeviceStore) Create(
	ctx context.Context,
	record DeviceRecord,
) (string, string, error) {
	deviceCode, err := RandomToken(32)
	if err != nil {
		return "", "", err
	}

	now := time.Now()
	record.Status = DeviceStatusPending
	record.CreatedAt = now.Unix()
	record.ExpiresAt = now.Add(deviceTTL).Unix()

	for attempt := 0; attempt < userCodeCreateAttempts; attempt++ {
		userCode, codeErr := randomUserCode()
		if codeErr != nil {
			return "", "", codeErr
		}

		ok, setErr := s.client.SetNX(
			ctx,
			deviceUserCodeKeyPrefix+userCode,
			[]byte(deviceCode),
			deviceTTL,
		)
		if setErr != nil {
			return "", "", setErr
		}
		if !ok {
			continue
		}

		record.UserCode = userCode
		data, marshalErr := json.Marshal(record)
		if marshalErr != nil {
			return "", "", marshalErr
		}
		ok, setErr = s.client.SetNX(ctx, deviceKeyPrefix+deviceCode, data, deviceTTL)
		if setErr != nil {
			return "", "", setErr
		}
		if !ok {
			return "", "", ErrConflict
		}
		return deviceCode, userCode, nil
	}
	return "", "", ErrConflict
}

func (s *KVDeviceStore) Get(ctx context.Context, deviceCode string) (DeviceRecord, error) {
	data, err := s.client.Get(ctx, deviceKeyPrefix+deviceCode)
	if errors.Is(err, kv.ErrKeyNotFound) {
		return DeviceRecord{}, ErrNotFound
	}
	if err != nil {
		return DeviceRecord{}, err
	}

	var record DeviceRecord
	err = json.Unmarshal(data, &record)
	if err != nil {
		return DeviceRecord{}, err
	}
	return record, nil
}

// GetByUserCode resolves a normalized user code to its device authorization.
func (s *KVDeviceStore) GetByUserCode(
	ctx context.Context,
	userCode string,
) (string, DeviceRecord, error) {
	data, err := s.client.Get(ctx, deviceUserCodeKeyPrefix+userCode)
	if errors.Is(err, kv.ErrKeyNotFound) {
		return "", DeviceRecord{}, ErrNotFound
	}
	if err != nil {
		return "", DeviceRecord{}, err
	}

	deviceCode := string(data)
	record, err := s.Get(ctx, deviceCode)
	if err != nil {
		return "", DeviceRecord{}, err
	}
	return deviceCode, record, nil
}

// Update rewrites the device record, preserving the remaining TTL.
func (s *KVDeviceStore) Update(
	ctx context.Context,
	deviceCode string,
	record DeviceRecord,
) error {
	key := deviceKeyPrefix + deviceCode
	ttl, err := s.client.TTL(ctx, key)
	if err != nil || ttl <= 0 {
		return ErrNotFound
	}

	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return s.client.Set(ctx, key, data, ttl)
}

// ConsumeApproved atomically claims an approved device authorization so
// concurrent polls cannot both mint tokens. Pending or denied records are
// returned unmodified with claimed=false.
func (s *KVDeviceStore) ConsumeApproved(
	ctx context.Context,
	deviceCode string,
) (DeviceRecord, bool, error) {
	ctx, span := tracing.StartSpan(ctx, "authn.oidc.device.consume")
	defer span.End()

	key := deviceKeyPrefix + deviceCode
	data, err := s.client.Get(ctx, key)
	if errors.Is(err, kv.ErrKeyNotFound) {
		return DeviceRecord{}, false, ErrNotFound
	}
	if err != nil {
		return DeviceRecord{}, false, err
	}

	var record DeviceRecord
	err = json.Unmarshal(data, &record)
	if err != nil {
		return DeviceRecord{}, false, err
	}
	if record.Status != DeviceStatusApproved {
		return record, false, nil
	}

	claimed, err := s.client.CompareAndDelete(ctx, key, data)
	if err != nil {
		return DeviceRecord{}, false, err
	}
	if !claimed {
		return DeviceRecord{}, false, ErrNotFound
	}

	s.client.Delete(ctx, deviceUserCodeKeyPrefix+record.UserCode)
	return record, true, nil
}

// Delete removes the device authorization and its user-code lookup.
func (s *KVDeviceStore) Delete(ctx context.Context, deviceCode, userCode string) error {
	if userCode != "" {
		s.client.Delete(ctx, deviceUserCodeKeyPrefix+userCode)
	}
	err := s.client.Delete(ctx, deviceKeyPrefix+deviceCode)
	if errors.Is(err, kv.ErrKeyNotFound) {
		return nil
	}
	return err
}

// AllowPoll enforces the RFC 8628 poll interval: the first call within each
// interval window returns true, later ones return false (slow_down).
func (s *KVDeviceStore) AllowPoll(
	ctx context.Context,
	deviceCode string,
	interval time.Duration,
) (bool, error) {
	if interval <= 0 {
		return true, nil
	}
	return s.client.SetNX(ctx, devicePollKeyPrefix+deviceCode, []byte{1}, interval)
}
