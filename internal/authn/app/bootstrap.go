package app

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	profilepb "sanzi.io/muid/api/proto/profile/v1"
	"sanzi.io/muid/infra/nats"
	"sanzi.io/muid/infra/redis"
	authnent "sanzi.io/muid/internal/authn/ent"
	"sanzi.io/muid/internal/authn/infra/account"
	"sanzi.io/muid/internal/authn/infra/kv"
	"sanzi.io/muid/pkg/errutil"
	"sanzi.io/muid/pkg/traceid"
)

func closeIfCloser(v any) {
	if c, ok := v.(io.Closer); ok {
		errutil.Discard(c.Close())
	}
}

// NewAuthnInfra wires Redis-backed OTP / transition stores, NATS, Ent, optional Profile gRPC, and the identity manager.
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

	entClient, err := authnent.Open("pgx", cfg.DatabaseURL)
	if err != nil {
		closeIfCloser(pubSub)
		closeIfCloser(redisKV)
		return nil, fmt.Errorf("ent open: %w", err)
	}

	if err := entClient.Schema.Create(ctx); err != nil {
		msg := strings.ToLower(err.Error())
		if strings.Contains(msg, "already exists") || strings.Contains(msg, "duplicate") {
			log.Printf("authn ent: reusing existing schema (%v)", err)
		} else {
			errutil.Discard(entClient.Close())
			closeIfCloser(pubSub)
			closeIfCloser(redisKV)
			return nil, fmt.Errorf("authn ent schema: %w", err)
		}
	}

	var profileConn *grpc.ClientConn
	var profileCli profilepb.ProfileServiceClient
	if addr := strings.TrimSpace(cfg.ProfileGRPCAddr); addr != "" {
		profileConn, err = grpc.NewClient(
			addr,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithUnaryInterceptor(traceid.UnaryClientInterceptor()),
		)
		if err != nil {
			errutil.Discard(entClient.Close())
			closeIfCloser(pubSub)
			closeIfCloser(redisKV)
			return nil, fmt.Errorf("profile grpc dial: %w", err)
		}
		profileCli = profilepb.NewProfileServiceClient(profileConn)
	}

	accounts := &account.Services{
		DB:                 entClient,
		Profile:            profileCli,
		ProfileCallTimeout: time.Duration(cfg.ProfileGRPCTimeoutSeconds) * time.Second,
	}

	ipm, err := InitializeIdentityManager(
		ctx,
		cfg,
		transitionStore,
		otpStore,
		pubSub,
		accounts,
	)
	if err != nil {
		if profileConn != nil {
			errutil.Discard(profileConn.Close())
		}
		errutil.Discard(entClient.Close())
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
		Accounts:        accounts,
		entClient:       entClient,
		profileConn:     profileConn,
	}, nil
}
