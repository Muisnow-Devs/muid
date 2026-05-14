package kv

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
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
	Attempts int       `json:"attempts"`
	ExpireAt time.Time `json:"expire_at"`
}

type KVOTPStore struct {
	client    kv.KVStore
	otpSecret []byte
}

func NewKVOTPStore(kvStore kv.KVStore, otpSecret []byte) otp.OTPStore {
	return &KVOTPStore{client: kvStore, otpSecret: otpSecret}
}

func (*KVOTPStore) key(transitionId string) string {
	return "muid:challenge:otp:" + transitionId
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
	expiration time.Duration,
) (otp.OTPChallenge, error) {
	otpCode, err := generateOTP(OTPLength)
	if err != nil {
		return otp.OTPChallenge{}, err
	}

	sha := store.hashOTP(otpCode, transitionId)
	expiresAt := time.Now().Add(expiration)
	info := OTPInformation{
		OTPHash:  sha[:],
		Attempts: 0,
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

	return otp.OTPChallenge{
		OTP:       otpCode,
		ExpiresAt: expiresAt,
	}, nil
}

func (store *KVOTPStore) VerifyOTP(
	ctx context.Context,
	transitionId, code string,
) error {
	if code == "" || len(code) != OTPLength {
		return otp.ErrOTPInvalid
	}

	data, err := store.client.Get(ctx, store.key(transitionId))
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
