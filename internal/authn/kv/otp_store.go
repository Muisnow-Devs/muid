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

type otpInformation struct {
	OTPHash    []byte    `json:"otp_hash"`
	Attempts   int       `json:"attempts"`
	ExpireAt   time.Time `json:"expire_at"`
	LastSentAt time.Time `json:"last_sent_at,omitempty"`
}

// recipientSendState tracks the last OTP send for a normalized recipient so send
// cooldown can apply across transitions (mirrors otpInformation cooldown rules).
type recipientSendState struct {
	LastSentAt time.Time `json:"last_sent_at"`
	ExpireAt   time.Time `json:"expire_at"`
}

type KVOTPStore struct {
	client       kv.KVStore
	otpSecret    []byte
	sendCooldown time.Duration
}

// NewKVOTPStore returns a KV-backed OTP store.
func NewKVOTPStore(kvStore kv.KVStore, otpSecret []byte, sendCooldown time.Duration) otp.OTPStore {
	return &KVOTPStore{client: kvStore, otpSecret: otpSecret, sendCooldown: sendCooldown}
}

func (*KVOTPStore) key(transitionId string) string {
	return "muid:challenge:otp:" + transitionId
}

func (*KVOTPStore) recipientCooldownKey(normalizedEmail string) string {
	return "muid:challenge:otp_recipient_send:" + normalizedEmail
}

func normalizeOTPRecipient(s string) string {
	return strings.TrimSpace(strings.ToLower(s))
}

func (store *KVOTPStore) recipientStateKVTTL(challengeTTL time.Duration) time.Duration {
	if store.sendCooldown <= 0 {
		return challengeTTL
	}
	ttl := challengeTTL
	if ttl < store.sendCooldown {
		ttl = store.sendCooldown
	}
	if ttl <= 0 {
		ttl = store.sendCooldown
	}
	return ttl
}

func (store *KVOTPStore) hashOTP(otp string, transitionId string) []byte {
	mac := hmac.New(sha256.New, store.otpSecret)

	mac.Write([]byte(otp))
	mac.Write([]byte{0})
	mac.Write([]byte(transitionId))

	return mac.Sum(nil)
}

func equalHashes(a, b []byte) bool {
	return hmac.Equal(a, b)
}

func generateOTP(length int) (string, error) {
	seed := "0123456789"
	otp := make([]byte, length)
	for i := range otp {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(seed))))
		if err != nil {
			return "", err
		}
		otp[i] = seed[num.Int64()]
	}
	return string(otp), nil
}

func (store *KVOTPStore) CreateOTP(
	ctx context.Context,
	transitionId string,
	recipient string,
	expiration time.Duration,
) (otp.OTPChallenge, error) {
	ctx, span := tracing.StartSpan(ctx, "authn.otp.create")
	defer span.End()

	normalizedRecipient := normalizeOTPRecipient(recipient)

	if store.sendCooldown > 0 {
		err := store.checkSendCooldown(ctx, transitionId)
		if err != nil {
			return otp.OTPChallenge{}, err
		}
		if normalizedRecipient != "" {
			err = store.checkRecipientSendCooldown(ctx, normalizedRecipient)
			if err != nil {
				return otp.OTPChallenge{}, err
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
		OTPHash:    sha[:],
		Attempts:   0,
		ExpireAt:   expiresAt,
		LastSentAt: now,
	}

	jsonData, err := json.Marshal(info)
	if err != nil {
		return otp.OTPChallenge{}, err
	}

	err = store.client.Set(ctx, store.key(transitionId), jsonData, expiration)
	if err != nil {
		return otp.OTPChallenge{}, err
	}

	if store.sendCooldown > 0 && normalizedRecipient != "" {
		recipientState := recipientSendState{LastSentAt: now, ExpireAt: expiresAt}
		recipientJSON, err := json.Marshal(recipientState)
		if err != nil {
			return otp.OTPChallenge{}, err
		}
		recipientTTL := store.recipientStateKVTTL(expiration)
		err = store.client.Set(
			ctx,
			store.recipientCooldownKey(normalizedRecipient),
			recipientJSON,
			recipientTTL,
		)
		if err != nil {
			return otp.OTPChallenge{}, err
		}
	}

	return otp.OTPChallenge{
		OTP:       otpCode,
		ExpiresAt: expiresAt,
	}, nil
}

func (store *KVOTPStore) checkSendCooldown(ctx context.Context, transitionId string) error {
	data, err := store.client.Get(ctx, store.key(transitionId))
	if err == kv.ErrKeyNotFound {
		return nil
	}
	if err != nil {
		return err
	}

	var info otpInformation
	err = json.Unmarshal(data, &info)
	if err != nil {
		return err
	}

	now := time.Now()
	if now.After(info.ExpireAt) {
		return nil
	}
	if !info.LastSentAt.IsZero() && now.Sub(info.LastSentAt) < store.sendCooldown {
		return otp.ErrOTPSendRateLimited
	}
	return nil
}

func (store *KVOTPStore) checkRecipientSendCooldown(
	ctx context.Context,
	normalizedEmail string,
) error {
	data, err := store.client.Get(ctx, store.recipientCooldownKey(normalizedEmail))
	if err == kv.ErrKeyNotFound {
		return nil
	}
	if err != nil {
		return err
	}

	var info recipientSendState
	err = json.Unmarshal(data, &info)
	if err != nil {
		return err
	}

	now := time.Now()
	if now.After(info.ExpireAt) {
		return nil
	}
	if !info.LastSentAt.IsZero() && now.Sub(info.LastSentAt) < store.sendCooldown {
		return otp.ErrOTPSendRateLimited
	}
	return nil
}

func (store *KVOTPStore) VerifyOTP(
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

	if !equalHashes(info.OTPHash, sha) {
		info.Attempts++

		if info.Attempts >= 3 {
			store.RevokeOTP(ctx, transitionId)
			return otp.ErrTooManyAttempts
		}

		// Preserve LastSentAt so resend cooldown still applies after failed attempts.
		ttl := time.Until(info.ExpireAt)
		jsonData, _ := json.Marshal(info)
		store.client.Set(ctx, store.key(transitionId), jsonData, ttl)

		return otp.ErrOTPInvalid
	}

	store.RevokeOTP(ctx, transitionId)
	return nil
}

func (store *KVOTPStore) RevokeOTP(ctx context.Context, transitionId string) error {
	return store.client.Delete(ctx, store.key(transitionId))
}
