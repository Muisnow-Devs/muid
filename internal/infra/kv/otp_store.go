package kv

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"time"

	"sanzi.io/muid/internal/otp"
	"sanzi.io/muid/pkg/shared/kv"
)

const (
	OTPLength = 6
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

func (store KVOTPStore) CreateOTP(
	ctx context.Context,
	session string,
	expiration time.Duration,
) (string, error) {
	iv := make([]byte, 16)
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}

	otp, err := generateOTP(OTPLength)
	if err != nil {
		return "", err
	}

	sha := store.hashOTP(string(otp), iv)
	info := OTPInformation{
		OTPHash:  sha[:],
		IV:       iv,
		Attempts: 0,
		ExpireAt: time.Now().Add(expiration),
	}

	jsonData, err := json.Marshal(info)
	if err != nil {
		return "", err
	}

	err = store.client.Set(ctx, key(session), jsonData, expiration)
	if err != nil {
		return "", err
	}

	return string(otp), nil
}

func (store KVOTPStore) VerifyOTP(ctx context.Context, session, code string) error {
	if code == "" || len(code) != OTPLength {
		return otp.ErrOTPInvalid
	}

	data, err := store.client.Get(ctx, key(session))
	if err == kv.ErrKeyNotFound {
		return otp.ErrOTPInvalid
	}

	if err != nil {
		return err
	}

	var info OTPInformation
	if err := json.Unmarshal(data, &info); err != nil {
		return err
	}

	if time.Now().After(info.ExpireAt) {
		store.RevokeOTP(ctx, session)
		return otp.ErrOTPExpired
	}

	sha := store.hashOTP(code, info.IV)

	if !equalHashes(info.OTPHash, sha) {
		info.Attempts++

		if info.Attempts >= 3 {
			store.RevokeOTP(ctx, session)
			return otp.ErrTooManyAttempts
		}

		ttl := time.Until(info.ExpireAt)
		jsonData, _ := json.Marshal(info)
		store.client.Set(ctx, key(session), jsonData, ttl)

		return otp.ErrOTPInvalid
	}

	store.RevokeOTP(ctx, session)
	return nil
}

func (store KVOTPStore) RevokeOTP(ctx context.Context, session string) error {
	return store.client.Delete(ctx, key(session))
}
