package kv

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"math/big"
	"strings"
	"time"

	"sanzi.io/muid/internal/otp"
	"sanzi.io/muid/pkg/shared/kv"
	"sanzi.io/muid/pkg/shared/tracing"
)

const otpLength = 6
const maxAttempts = 3
const keyBase = "muid:challenge:otp:"

// otpInformation is stored in the KV under the challenge key.
// Attempts are tracked separately via the attempts counter key.
// Send cooldowns are tracked via dedicated TTL-sentinel keys.
type otpInformation struct {
	OTPHash  []byte    `json:"otp_hash"`
	ExpireAt time.Time `json:"expire_at"`
}

type kvOTPStore struct {
	client       kv.AtomicKVStore
	otpSecret    []byte
	sendCooldown time.Duration
}

// NewKVOTPStore returns a KV-backed OTP store.
func NewKVOTPStore(
	kvStore kv.AtomicKVStore,
	otpSecret []byte,
	sendCooldown time.Duration,
) otp.OTPStore {
	return &kvOTPStore{client: kvStore, otpSecret: otpSecret, sendCooldown: sendCooldown}
}

// key is the primary challenge key: stores otpInformation.
func (*kvOTPStore) key(transitionId string) string {
	return keyBase + transitionId
}

// attemptsKey is the failed-attempt counter for a challenge.
func (*kvOTPStore) attemptsKey(transitionId string) string {
	return keyBase + transitionId + ":attempts"
}

// sendCooldownKey is a TTL sentinel that exists while the per-transition send cooldown is active.
func (*kvOTPStore) sendCooldownKey(transitionId string) string {
	return keyBase + transitionId + ":cooldown"
}

// recipientCooldownKey is a TTL sentinel that exists while the per-recipient send cooldown is active.
func (*kvOTPStore) recipientCooldownKey(normalizedEmail string) string {
	return "muid:challenge:otp_recipient_send:" + normalizedEmail
}

func normalizeOTPRecipient(s string) string {
	return strings.TrimSpace(strings.ToLower(s))
}

func (store *kvOTPStore) hashOTP(otpCode string, transitionId string) []byte {
	mac := hmac.New(sha256.New, store.otpSecret)
	mac.Write([]byte(otpCode))
	mac.Write([]byte{0})
	mac.Write([]byte(transitionId))
	return mac.Sum(nil)
}

func generateOTP(length int) (string, error) {
	seed := "0123456789"
	buf := make([]byte, length)
	for i := range buf {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(seed))))
		if err != nil {
			return "", err
		}
		buf[i] = seed[num.Int64()]
	}
	return string(buf), nil
}

func (store *kvOTPStore) CreateOTP(
	ctx context.Context,
	transitionId string,
	recipient string,
	expiration time.Duration,
) (otp.OTPChallenge, error) {
	ctx, span := tracing.StartSpan(ctx, "authn.otp.create")
	defer span.End()

	normalizedRecipient := normalizeOTPRecipient(recipient)

	if store.sendCooldown > 0 {
		cooling, err := store.client.Exists(ctx, store.sendCooldownKey(transitionId))
		if err != nil {
			return otp.OTPChallenge{}, err
		}
		if cooling {
			return otp.OTPChallenge{}, otp.ErrOTPSendRateLimited
		}

		if normalizedRecipient != "" {
			cooling, err = store.client.Exists(ctx, store.recipientCooldownKey(normalizedRecipient))
			if err != nil {
				return otp.OTPChallenge{}, err
			}
			if cooling {
				return otp.OTPChallenge{}, otp.ErrOTPSendRateLimited
			}
		}
	}

	// Send is allowed; drop any existing challenge before issuing a new code.
	err := store.RevokeOTP(ctx, transitionId)
	if err != nil {
		return otp.OTPChallenge{}, err
	}

	otpCode, err := generateOTP(otpLength)
	if err != nil {
		return otp.OTPChallenge{}, err
	}

	sha := store.hashOTP(otpCode, transitionId)
	now := time.Now()
	expiresAt := now.Add(expiration)
	info := otpInformation{
		OTPHash:  sha[:],
		ExpireAt: expiresAt,
	}

	jsonData, err := json.Marshal(info)
	if err != nil {
		return otp.OTPChallenge{}, err
	}

	err = store.client.Set(ctx, store.key(transitionId), jsonData, expiration)
	if err != nil {
		return otp.OTPChallenge{}, err
	}

	// Only set cooldown sentinels when the challenge is not already expired.
	// A non-positive expiration means the challenge is immediately stale; no cooldown applies.
	if store.sendCooldown > 0 && expiration > 0 {
		// Transition-level cooldown: cleared by RevokeOTP so resend after revoke is permitted.
		store.client.SetNX(ctx, store.sendCooldownKey(transitionId), []byte{1}, store.sendCooldown)

		// Recipient-level cooldown: cross-transition, expires naturally.
		if normalizedRecipient != "" {
			store.client.SetNX(
				ctx,
				store.recipientCooldownKey(normalizedRecipient),
				[]byte{1},
				store.sendCooldown,
			)
		}
	}

	return otp.OTPChallenge{
		OTP:       otpCode,
		ExpiresAt: expiresAt,
	}, nil
}

func (store *kvOTPStore) VerifyOTP(
	ctx context.Context,
	transitionId, code string,
) error {
	ctx, span := tracing.StartSpan(ctx, "authn.otp.verify")
	defer span.End()

	if code == "" || len(code) != otpLength {
		return otp.ErrOTPInvalid
	}

	data, err := store.client.Get(ctx, store.key(transitionId))
	if err == kv.ErrKeyNotFound {
		return otp.ErrOTPInvalid
	}
	if err != nil {
		return err
	}

	var info otpInformation
	err = json.Unmarshal(data, &info)
	if err != nil {
		return err
	}

	if time.Now().After(info.ExpireAt) {
		store.RevokeOTP(ctx, transitionId)
		return otp.ErrOTPExpired
	}

	sha := store.hashOTP(code, transitionId)

	// Use CompareAndDelete for an atomic check-and-revoke on success:
	// only deletes the key if the stored value still matches what we read,
	// preventing double-use under concurrent verification calls.
	if hmac.Equal(info.OTPHash, sha) {
		deleted, err := store.client.CompareAndDelete(ctx, store.key(transitionId), data)
		if err != nil {
			return err
		}
		if !deleted {
			// Another concurrent verify won the race; treat as invalid.
			return otp.ErrOTPInvalid
		}
		// Clean up ancillary keys on successful verify.
		store.client.Delete(ctx, store.attemptsKey(transitionId))
		store.client.Delete(ctx, store.sendCooldownKey(transitionId))
		return nil
	}

	// Wrong code — atomically increment the attempts counter, aligned to the challenge TTL.
	ttl, err := store.client.TTL(ctx, store.key(transitionId))
	if err != nil || ttl <= 0 {
		// Challenge has expired or disappeared between Get and now.
		return otp.ErrOTPInvalid
	}

	attempts, err := store.client.Increment(ctx, store.attemptsKey(transitionId))
	if err != nil {
		return err
	}
	store.client.Expire(ctx, store.attemptsKey(transitionId), ttl)

	if attempts >= maxAttempts {
		store.RevokeOTP(ctx, transitionId)
		return otp.ErrTooManyAttempts
	}

	return otp.ErrOTPInvalid
}

func (store *kvOTPStore) RevokeOTP(ctx context.Context, transitionId string) error {
	// Remove the challenge, its attempts counter, and the per-transition send cooldown.
	// The per-recipient cooldown is intentionally left to expire on its own.
	store.client.Delete(ctx, store.attemptsKey(transitionId))
	store.client.Delete(ctx, store.sendCooldownKey(transitionId))
	return store.client.Delete(ctx, store.key(transitionId))
}
