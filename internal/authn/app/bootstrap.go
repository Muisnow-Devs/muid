package app

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"entgo.io/ent/dialect"
	"google.golang.org/grpc"

	profilepb "sanzi.io/muid/api/proto/profile/v1"
	"sanzi.io/muid/infra/nats"
	"sanzi.io/muid/infra/redis"
	gcpsecretmanager "sanzi.io/muid/infra/secretmanager"
	"sanzi.io/muid/internal/authn/account"
	authnent "sanzi.io/muid/internal/authn/ent"
	"sanzi.io/muid/internal/authn/kv"
	"sanzi.io/muid/internal/signature"
	"sanzi.io/muid/pkg/entpostgres"
	"sanzi.io/muid/pkg/errutil"
	grpcutils "sanzi.io/muid/pkg/grpc_utils"
)

// NewAuthnInfra wires Redis-backed OTP / transition stores, NATS, Ent, optional Profile gRPC, and the identity manager.
func NewAuthnInfra(ctx context.Context, cfg Config) (*InfraDependencies, error) {
	redisKV := redis.NewRedisKVStore(cfg.RedisURL)

	otpSecret, err := hex.DecodeString(cfg.OTPSecretKey)
	if err != nil {
		errutil.CloseIf(redisKV)
		return nil, fmt.Errorf("invalid OTP secret key: %w, should be a valid hex string", err)
	}

	otpSendCooldown := time.Duration(cfg.OTPSendCooldownSeconds) * time.Second
	if cfg.OTPSendCooldownSeconds < 0 {
		otpSendCooldown = 0
	}
	otpStore := kv.NewKVOTPStore(redisKV, otpSecret, otpSendCooldown)

	pubSub, err := nats.NewNATSPubSub(cfg.NATSURL)
	if err != nil {
		errutil.CloseIf(redisKV)
		return nil, fmt.Errorf("nats: %w", err)
	}

	transitionStore := kv.NewKVAuthTransitionStore(redisKV)
	sessionCache := kv.NewKVSessionCache(redisKV)

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
		profileConn, err = grpcutils.DialInsecureClient(addr, profileGRPCResilience(cfg))
		if err != nil {
			errutil.Close(entClient)
			errutil.CloseIf(pubSub)
			errutil.CloseIf(redisKV)
			return nil, fmt.Errorf("profile grpc dial: %w", err)
		}
		profileCli = profilepb.NewProfileServiceClient(profileConn)
	}

	signatureManager, err := newSignatureManager(ctx, cfg)
	if err != nil {
		errutil.Close(profileConn)
		errutil.Close(entClient)
		errutil.CloseIf(pubSub)
		errutil.CloseIf(redisKV)
		return nil, fmt.Errorf("signature manager: %w", err)
	}

	store := &account.Store{
		DB:                 entClient,
		Profile:            profileCli,
		ProfileCallTimeout: time.Duration(cfg.ProfileGRPCTimeoutSeconds) * time.Second,
		SessionCache:       sessionCache,
	}
	accounts := account.New(store, pubSub)

	ipm, err := InitializeIdentityManager(
		ctx,
		cfg,
		transitionStore,
		otpStore,
		pubSub,
		accounts,
	)
	if err != nil {
		errutil.CloseIf(signatureManager)
		errutil.Close(profileConn)
		errutil.Close(entClient)
		errutil.CloseIf(pubSub)
		errutil.CloseIf(redisKV)
		return nil, fmt.Errorf("identity manager: %w", err)
	}

	return &InfraDependencies{
		GlobalConfig:     cfg,
		Redis:            redisKV,
		OTPStore:         otpStore,
		TransitionStore:  transitionStore,
		SessionCache:     sessionCache,
		PubSub:           pubSub,
		IdentityManager:  ipm,
		Accounts:         accounts,
		SignatureManager: signatureManager,
		entClient:        entClient,
		profileConn:      profileConn,
	}, nil
}

func newSignatureManager(ctx context.Context, cfg Config) (signature.SignatureManager, error) {
	if strings.TrimSpace(cfg.SignatureSecretName) == "" {
		return nil, nil
	}

	secretStore, err := gcpsecretmanager.NewGCPSecretManager(ctx, gcpsecretmanager.GCPConfig{
		ProjectID:       cfg.SecretManagerGCPProjectID,
		CredentialsFile: cfg.SecretManagerGCPCredentials,
	})
	if err != nil {
		return nil, err
	}

	manager, err := signature.NewSignatureManager(secretStore, signature.ManagerConfig{
		SecretName:          cfg.SignatureSecretName,
		KeyBits:             cfg.SignatureKeyBits,
		PreviousGenerations: cfg.SignaturePreviousGenerations,
		RotationPeriod:      signatureRotationPeriod(cfg),
	})
	if err != nil {
		errutil.CloseIf(secretStore)
		return nil, err
	}
	return manager, nil
}

func signatureRotationPeriod(cfg Config) time.Duration {
	if cfg.SignatureRotationPeriodHours <= 0 {
		return -1
	}
	return time.Duration(cfg.SignatureRotationPeriodHours) * time.Hour
}

func profileGRPCResilience(cfg Config) grpcutils.ClientResilienceConfig {
	maxRetries := cfg.ProfileGRPCMaxRetries
	if maxRetries < 0 {
		maxRetries = 0
	}
	cbFailures := uint32(cfg.ProfileGRPCCBConsecutiveFailures)
	if cbFailures == 0 {
		cbFailures = 5
	}
	halfOpen := uint32(cfg.ProfileGRPCCBHalfOpenMaxRequests)
	if halfOpen == 0 {
		halfOpen = 3
	}
	openSec := cfg.ProfileGRPCCBOpenSeconds
	if openSec <= 0 {
		openSec = 30
	}
	backoffMs := cfg.ProfileGRPCRetryBackoffMillis
	if backoffMs <= 0 {
		backoffMs = 100
	}
	maxBackoffMs := cfg.ProfileGRPCRetryMaxBackoffMillis
	if maxBackoffMs <= 0 {
		maxBackoffMs = 2000
	}
	return grpcutils.ClientResilienceConfig{
		Retry: grpcutils.RetryConfig{
			MaxRetries:  maxRetries,
			BaseBackoff: time.Duration(backoffMs) * time.Millisecond,
			MaxBackoff:  time.Duration(maxBackoffMs) * time.Millisecond,
		},
		CircuitBreaker: grpcutils.CircuitBreakerConfig{
			Enabled:             cfg.ProfileGRPCCBEnabled,
			Name:                "authn-profile",
			MaxRequests:         halfOpen,
			ConsecutiveFailures: cbFailures,
			OpenTimeout:         time.Duration(openSec) * time.Second,
		},
	}
}
