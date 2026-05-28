package app

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"entgo.io/ent/dialect"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"google.golang.org/grpc"

	profilepb "sanzi.io/muid/api/proto/profile/v1"
	"sanzi.io/muid/infra/nats"
	"sanzi.io/muid/infra/redis"
	authnent "sanzi.io/muid/internal/authn/ent"
	authnkv "sanzi.io/muid/internal/authn/kv"
	"sanzi.io/muid/internal/identity"
	"sanzi.io/muid/pkg/entpostgres"
	"sanzi.io/muid/pkg/errutil"
	grpcutils "sanzi.io/muid/pkg/grpc_utils"
)

// NewAuthnInfra wires Redis-backed OTP / transition stores, NATS, Ent, optional Profile gRPC, and WebAuthn.
func NewAuthnInfra(ctx context.Context, cfg Config) (*InfraDependencies, error) {
	redisKV := redis.NewRedisKVStore(cfg.RedisAddr, cfg.RedisDatabase)

	otpSecret, err := hex.DecodeString(cfg.OTPSecretKey)
	if err != nil {
		errutil.CloseIf(redisKV)
		return nil, fmt.Errorf("invalid OTP secret key: %w, should be a valid hex string", err)
	}

	otpSendCooldown := time.Duration(cfg.OTPSendCooldownSeconds) * time.Second
	if cfg.OTPSendCooldownSeconds < 0 {
		otpSendCooldown = 0
	}
	otpStore := authnkv.NewKVOTPStore(redisKV, otpSecret, otpSendCooldown)

	pubSub, err := nats.NewNATSPubSub(cfg.NATSURL)
	if err != nil {
		errutil.CloseIf(redisKV)
		return nil, fmt.Errorf("nats: %w", err)
	}

	transitionStore := authnkv.NewKVAuthTransitionStore(redisKV)
	sessionCache := authnkv.NewKVSessionCache(redisKV)

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

	// Initialize WebAuthn
	wa, err := webauthn.New(&webauthn.Config{
		RPID:          cfg.PasskeyRPID,
		RPDisplayName: cfg.PasskeyRPDisplayName,
		RPOrigins:     cfg.PasskeyRPOrigins,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			UserVerification: protocol.VerificationPreferred,
			ResidentKey:      protocol.ResidentKeyRequirementPreferred,
		},
		AttestationPreference: protocol.PreferNoAttestation,
		Timeouts: webauthn.TimeoutsConfig{
			Login:        webauthn.TimeoutConfig{Enforce: true, Timeout: time.Minute},
			Registration: webauthn.TimeoutConfig{Enforce: true, Timeout: time.Minute},
		},
	})
	if err != nil {
		errutil.Close(profileConn)
		errutil.Close(entClient)
		errutil.CloseIf(pubSub)
		errutil.CloseIf(redisKV)
		return nil, fmt.Errorf("webauthn: %w", err)
	}

	identityMgr, err := identity.NewIdentityManager(
		ctx,
		entClient,
		otpStore,
		transitionStore,
		pubSub,
		wa,
		cfg.OTPSendCooldownSeconds,
		cfg.OIDCClients,
	)
	if err != nil {
		errutil.Close(profileConn)
		errutil.Close(entClient)
		errutil.CloseIf(pubSub)
		errutil.CloseIf(redisKV)
		return nil, fmt.Errorf("identity manager: %w", err)
	}

	return &InfraDependencies{
		GlobalConfig:              cfg,
		Redis:                     redisKV,
		OTPStore:                  otpStore,
		TransitionStore:           transitionStore,
		SessionCache:              sessionCache,
		PubSub:                    pubSub,
		WebAuthn:                  wa,
		ProfileCli:                profileCli,
		ProfileCallTimeoutSeconds: time.Duration(cfg.ProfileGRPCTimeoutSeconds) * time.Second,
		IdentityManager:           identityMgr,
		entClient:                 entClient,
		profileConn:               profileConn,
	}, nil
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
