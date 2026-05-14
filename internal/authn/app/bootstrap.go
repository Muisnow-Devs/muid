package app

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"entgo.io/ent/dialect"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	profilepb "sanzi.io/muid/api/proto/profile/v1"
	"sanzi.io/muid/infra/nats"
	"sanzi.io/muid/infra/redis"
	authnent "sanzi.io/muid/internal/authn/ent"
	"sanzi.io/muid/internal/authn/infra/account"
	"sanzi.io/muid/internal/authn/infra/kv"
	"sanzi.io/muid/pkg/entpostgres"
	"sanzi.io/muid/pkg/errutil"
	"sanzi.io/muid/pkg/traceid"
)

// NewAuthnInfra wires Redis-backed OTP / transition stores, NATS, Ent, optional Profile gRPC, and the identity manager.
func NewAuthnInfra(ctx context.Context, cfg Config) (*InfraDependencies, error) {
	redisKV := redis.NewRedisKVStore(cfg.RedisURL)

	otpSecret, err := hex.DecodeString(cfg.OTPSecretKey)
	if err != nil {
		errutil.CloseIf(redisKV)
		return nil, fmt.Errorf("invalid OTP secret key: %w, should be a valid hex string", err)
	}

	otpStore := kv.NewKVOTPStore(redisKV, otpSecret)

	pubSub, err := nats.NewNATSPubSub(cfg.NATSURL)
	if err != nil {
		errutil.CloseIf(redisKV)
		return nil, fmt.Errorf("nats: %w", err)
	}

	transitionStore := kv.NewKVAuthTransitionStore(redisKV)

	fatalCleanup := func() {
		errutil.CloseIf(pubSub)
		errutil.CloseIf(redisKV)
	}
	entClient, _, err := entpostgres.OpenEntPostgres(ctx, cfg.DatabaseURL,
		func(d dialect.Driver) *authnent.Client {
			return authnent.NewClient(authnent.Driver(d))
		},
		func(c *authnent.Client) entpostgres.SchemaMigrator { return c.Schema },
		fatalCleanup,
		"authn ent: ",
	)
	if err != nil {
		return nil, err
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
			errutil.Close(entClient)
			errutil.CloseIf(pubSub)
			errutil.CloseIf(redisKV)
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
		errutil.Close(profileConn)
		errutil.Close(entClient)
		errutil.CloseIf(pubSub)
		errutil.CloseIf(redisKV)
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
