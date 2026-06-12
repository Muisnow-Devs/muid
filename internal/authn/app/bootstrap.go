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

	authzpb "sanzi.io/muid/api/proto/authz/v1"
	profilepb "sanzi.io/muid/api/proto/profile/v1"
	"sanzi.io/muid/infra/nats"
	"sanzi.io/muid/infra/redis"
	gcpsecretmanager "sanzi.io/muid/infra/secretmanager"
	authnent "sanzi.io/muid/internal/authn/ent"
	authnkv "sanzi.io/muid/internal/authn/kv"
	oidcstore "sanzi.io/muid/internal/authn/oidc/store"
	"sanzi.io/muid/internal/identity"
	"sanzi.io/muid/internal/signature"
	"sanzi.io/muid/pkg/authzclient"
	"sanzi.io/muid/pkg/entpostgres"
	"sanzi.io/muid/pkg/errutil"
	grpcutils "sanzi.io/muid/pkg/grpc_utils"
	"sanzi.io/muid/pkg/shared/kv"
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
	otpStore := authnkv.NewKVOTPStore(redisKV, otpSecret, otpSendCooldown, cfg.MaxAuthAttempts)

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

	deps := &InfraDependencies{
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
	}

	err = wireSignatureManager(ctx, cfg, deps)
	if err != nil {
		identityMgr.Close()
		errutil.Close(profileConn)
		errutil.Close(entClient)
		errutil.CloseIf(pubSub)
		errutil.CloseIf(redisKV)
		return nil, fmt.Errorf("signature manager: %w", err)
	}

	err = wireOIDCProviderInfra(ctx, cfg, redisKV, deps)
	if err != nil {
		errutil.CloseIf(deps.SignatureManager)
		identityMgr.Close()
		errutil.Close(profileConn)
		errutil.Close(entClient)
		errutil.CloseIf(pubSub)
		errutil.CloseIf(redisKV)
		return nil, fmt.Errorf("oidc provider: %w", err)
	}

	return deps, nil
}

// wireSignatureManager opens the owner-mode SignatureManager (authn rotates
// the signing keys and serves them via GetPublicKeys) whenever
// AUTHN_SIGNATURE_SECRET_NAME is set. The OIDC provider and session access
// tokens both require it.
func wireSignatureManager(ctx context.Context, cfg Config, deps *InfraDependencies) error {
	if !cfg.SignatureConfigured() {
		if cfg.OIDCProviderEnabled() {
			return fmt.Errorf(
				"AUTHN_SIGNATURE_SECRET_NAME is required when AUTHN_OIDC_ISSUER is set",
			)
		}
		if cfg.SessionAccessTokenEnabled() {
			return fmt.Errorf(
				"AUTHN_SIGNATURE_SECRET_NAME is required when AUTHN_SESSION_ACCESS_TOKEN_ISSUER is set",
			)
		}
		return nil
	}

	secretStore, err := gcpsecretmanager.NewGCPSecretManager(ctx, gcpsecretmanager.GCPConfig{
		ProjectID:       cfg.SecretManagerGCPProjectID,
		CredentialsFile: cfg.SecretManagerGCPCredentials,
	})
	if err != nil {
		return fmt.Errorf("secret manager: %w", err)
	}

	signatureManager, err := signature.NewSignatureManager(secretStore, signature.ManagerConfig{
		SecretName:          cfg.SignatureSecretName,
		KeyBits:             cfg.SignatureKeyBits,
		PreviousGenerations: cfg.SignaturePreviousGenerations,
		RotationPeriod:      signatureRotationPeriod(cfg),
	})
	if err != nil {
		errutil.CloseIf(secretStore)
		return err
	}

	deps.SignatureManager = signatureManager
	return nil
}

// signatureRotationPeriod maps the configured rotation hours onto the
// rotation ticker; non-positive disables the rotation job.
func signatureRotationPeriod(cfg Config) time.Duration {
	if cfg.SignatureRotationPeriodHours <= 0 {
		return -1
	}
	return time.Duration(cfg.SignatureRotationPeriodHours) * time.Hour
}

// wireOIDCProviderInfra adds the OP-specific dependencies (local authz
// enforcer, KV protocol stores) when AUTHN_OIDC_ISSUER is set. The
// SignatureManager is wired separately by wireSignatureManager. Without an
// issuer the OP surface stays disabled and the service boots as before.
func wireOIDCProviderInfra(
	ctx context.Context,
	cfg Config,
	redisKV kv.AtomicKVStore,
	deps *InfraDependencies,
) error {
	if !cfg.OIDCProviderEnabled() {
		return nil
	}
	authzAddr := strings.TrimSpace(cfg.AuthzGRPCAddr)
	if authzAddr == "" {
		return fmt.Errorf("AUTHN_AUTHZ_GRPC_ADDR is required when AUTHN_OIDC_ISSUER is set")
	}

	authzConn, err := grpcutils.DialInsecureClient(authzAddr, authzGRPCResilience(cfg))
	if err != nil {
		return fmt.Errorf("authz grpc dial: %w", err)
	}

	enforcer, err := authzclient.NewEnforcer(authzclient.Config{
		Namespace:       "authn",
		Client:          authzpb.NewAuthzServiceClient(authzConn),
		PubSub:          deps.PubSub,
		KV:              redisKV,
		RoleCacheTTL:    time.Duration(cfg.AuthzRoleCacheTTLSeconds) * time.Second,
		RefreshInterval: time.Duration(cfg.AuthzPolicyRefreshSeconds) * time.Second,
	})
	if err != nil {
		errutil.Close(authzConn)
		return fmt.Errorf("authz enforcer: %w", err)
	}
	err = enforcer.Start(ctx)
	if err != nil {
		errutil.Close(authzConn)
		return fmt.Errorf("authz enforcer start: %w", err)
	}

	deps.AuthzEnforcer = enforcer
	deps.OIDCCodes = oidcstore.NewKVCodeStore(redisKV)
	deps.OIDCPendings = oidcstore.NewKVPendingStore(redisKV)
	deps.OIDCDevices = oidcstore.NewKVDeviceStore(redisKV)
	deps.authzConn = authzConn
	return nil
}

// authzGRPCResilience reuses the Profile outbound resilience settings with a
// dedicated circuit-breaker name.
func authzGRPCResilience(cfg Config) grpcutils.ClientResilienceConfig {
	out := profileGRPCResilience(cfg)
	out.CircuitBreaker.Name = "authn-authz"
	return out
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
