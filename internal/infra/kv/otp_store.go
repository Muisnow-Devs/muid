package kv

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"time"

	"sanzi.io/muid/internal/otp"
	"sanzi.io/muid/pkg/shared/kv"
)

type OTPInformation struct {
	OTPHash  []byte    `json:"otp_hash"`
	IV       []byte    `json:"iv"`
	Attempts int       `json:"attempts"`
	ExpireAt time.Time `json:"expire_at"`
}

type KVOTPStore struct {
	client    kv.KVStore
	otpSecret []byte
}

func NewKVOTPStore(kvStore kv.KVStore, otpSecret []byte) otp.OTPStore {
	return KVOTPStore{client: kvStore, otpSecret: otpSecret}
}

func key(session string) string {
	sum := sha256.Sum256([]byte(session))
	return "muid:otp:" + hex.EncodeToString(sum[:])
}

func (store KVOTPStore) hashOTP(otp string, iv []byte) []byte {
	mac := hmac.New(sha256.New, store.otpSecret)
	mac.Write([]byte(otp))
	mac.Write(iv)
	return mac.Sum(nil)
}

func equalHashes(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

func (store KVOTPStore) SetOTP(ctx context.Context, session, code string, expiration time.Duration) error {
	iv := make([]byte, 16)
	if _, err := rand.Read(iv); err != nil {
		return err
	}

	sha := store.hashOTP(code, iv)
	info := OTPInformation{
		OTPHash:  sha[:],
		IV:       iv,
		Attempts: 0,
		ExpireAt: time.Now().Add(expiration),
	}

	jsonData, err := json.Marshal(info)
	if err != nil {
		return err
	}

	return store.client.Set(ctx, key(session), jsonData, expiration)
}

func (store KVOTPStore) VerifyOTP(ctx context.Context, session, code string) (bool, error) {
	data, err := store.client.Get(ctx, key(session))
	if err == kv.ErrKeyNotFound {
		return false, nil
	}

	if err != nil {
		return false, err
	}

	var info OTPInformation
	if err := json.Unmarshal(data, &info); err != nil {
		return false, err
	}

	if time.Now().After(info.ExpireAt) {
		store.RevokeOTP(ctx, session)
		return false, nil
	}

	sha := store.hashOTP(code, info.IV)

	if !equalHashes(info.OTPHash, sha) {
		info.Attempts++

		if info.Attempts >= 3 {
			store.RevokeOTP(ctx, session)
			return false, otp.ErrTooManyAttempts
		}

		ttl := time.Until(info.ExpireAt)
		jsonData, _ := json.Marshal(info)
		store.client.Set(ctx, key(session), jsonData, ttl)

		return false, nil
	}

	store.RevokeOTP(ctx, session)
	return true, nil
}

func (store KVOTPStore) RevokeOTP(ctx context.Context, session string) error {
	return store.client.Delete(ctx, key(session))
}
