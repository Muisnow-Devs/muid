package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"sanzi.io/muid/internal/authn/app"
	"sanzi.io/muid/internal/infra/kv"
	"sanzi.io/muid/pkg/shared"
	"sanzi.io/muid/pkg/shared/infra/nats"
	"sanzi.io/muid/pkg/shared/infra/redis"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("Application error: %v", err)
	}
}

func run() error {
	ctx := context.Background()

	config, err := shared.LoadConfig[app.Config](app.ConfigEnvPrefix)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	infraSvc, err := InitializeInfraService(ctx, config)
	if err != nil {
		return fmt.Errorf("init infra: %w", err)
	}

	authnApp, err := app.NewAuthnApp(ctx, infraSvc)
	if err != nil {
		return fmt.Errorf("create app: %w", err)
	}

	go func() {
		if err := authnApp.Start(ctx); err != nil {
			log.Printf("app start failed: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	authnApp.Stop()
	return nil
}

func InitializeInfraService(
	ctx context.Context,
	envConfig app.Config,
) (*app.InfraDependencies, error) {
	redisClient := redis.NewRedisKVStore(envConfig.RedisURL)

	otpSecret, err := hex.DecodeString(envConfig.OTPSecretKey)
	if err != nil {
		return nil, fmt.Errorf("invalid OTP secret key: %w, should be a valid hex string", err)
	}

	otpStore := kv.NewKVOTPStore(redisClient, otpSecret)
	pubSub, err := nats.NewNATSPubSub(envConfig.NATSURL)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize NATS pubsub: %w", err)
	}

	transitionStore := kv.NewKVAuthTransitionStore(redisClient)
	ipm, err := app.InitializeIdentityManager(
		ctx,
		envConfig,
		transitionStore,
		otpStore,
		pubSub,
		nil,
	) // passing nil for db placeholder since ent isn't initialized here yet
	if err != nil {
		return nil, fmt.Errorf("failed to initialize identity manager: %w", err)
	}

	infra := &app.InfraDependencies{
		GlobalConfig: envConfig,

		OTPStore:        otpStore,
		PubSub:          pubSub,
		IdentityManager: ipm,
	}

	return infra, nil
}
