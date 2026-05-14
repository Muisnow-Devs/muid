package app

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"

	"sanzi.io/muid/infra/nats"
	"sanzi.io/muid/infra/redis"
	"sanzi.io/muid/internal/authn/infra/kv"
	"sanzi.io/muid/pkg/errutil"
)

func closeIfCloser(v any) {
	if c, ok := v.(io.Closer); ok {
		errutil.Discard(c.Close())
	}
}

// NewAuthnInfra wires Redis-backed OTP / transition stores, NATS, and the identity manager (Ent client may be nil until wired in).
func NewAuthnInfra(ctx context.Context, cfg Config) (*InfraDependencies, error) {
	redisKV := redis.NewRedisKVStore(cfg.RedisURL)

	otpSecret, err := hex.DecodeString(cfg.OTPSecretKey)
	if err != nil {
		closeIfCloser(redisKV)
		return nil, fmt.Errorf("invalid OTP secret key: %w, should be a valid hex string", err)
	}

	otpStore := kv.NewKVOTPStore(redisKV, otpSecret)

	pubSub, err := nats.NewNATSPubSub(cfg.NATSURL)
	if err != nil {
		closeIfCloser(redisKV)
		return nil, fmt.Errorf("nats: %w", err)
	}

	transitionStore := kv.NewKVAuthTransitionStore(redisKV)

	ipm, err := InitializeIdentityManager(
		ctx,
		cfg,
		transitionStore,
		otpStore,
		pubSub,
		nil,
	)
	if err != nil {
		closeIfCloser(pubSub)
		closeIfCloser(redisKV)
		return nil, fmt.Errorf("identity manager: %w", err)
	}

	return &InfraDependencies{
		GlobalConfig:    cfg,
		Redis:           redisKV,
		OTPStore:        otpStore,
		TransitionStore: transitionStore,
		PubSub:          pubSub,
		IdentityManager: ipm,
	}, nil
}
