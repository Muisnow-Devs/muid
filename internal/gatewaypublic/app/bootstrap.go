package app

import (
	"context"
	"fmt"
	"strings"
	"time"

	"google.golang.org/grpc"

	authnpb "sanzi.io/muid/api/proto/authn/v1"
	authzpb "sanzi.io/muid/api/proto/authz/v1"
	profilepb "sanzi.io/muid/api/proto/profile/v1"
	"sanzi.io/muid/infra/geoip"
	"sanzi.io/muid/infra/redis"
	"sanzi.io/muid/infra/turnstile"
	"sanzi.io/muid/internal/gatewaypublic/graph"
	"sanzi.io/muid/internal/gatewaypublic/graph/persisted"
	"sanzi.io/muid/pkg/errutil"
	"sanzi.io/muid/pkg/gateway/csrf"
	"sanzi.io/muid/pkg/gateway/jwtauth"
	grpcutils "sanzi.io/muid/pkg/grpc_utils"
	"sanzi.io/muid/pkg/log"
	"sanzi.io/muid/pkg/mtls"
	"sanzi.io/muid/pkg/shared/kv"
)

// InfraDependencies holds the public gateway's wired infrastructure.
type InfraDependencies struct {
	GlobalConfig Config

	Redis     kv.AtomicKVStore
	Geo       geoip.Resolver
	Turnstile turnstile.Verifier
	CSRF      *csrf.Manager

	OIDCClient           authnpb.OIDCServiceClient
	AuthFlowClient       authnpb.AuthenticationFlowServiceClient
	SessionClient        authnpb.SessionServiceClient
	LinkedIdentityClient authnpb.LinkedIdentityServiceClient
	SigningKeyClient     authnpb.SigningKeyServiceClient

	// Data-plane clients (BFF fan-out) + local access-token JWT verifier.
	AuthzUserClient  authzpb.AuthzUserServiceClient
	AuthzOrgClient   authzpb.AuthzOrganizationAdminServiceClient
	ProfileClient    profilepb.ProfileServiceClient
	OrgProfileClient profilepb.OrganizationProfileServiceClient
	Verifier         graph.TokenVerifier

	// PersistedOps is the trusted-documents allowlist (hash→document). Empty in
	// debug mode; required (non-empty) otherwise.
	PersistedOps map[string]string

	authnConn   *grpc.ClientConn
	authzConn   *grpc.ClientConn
	profileConn *grpc.ClientConn
	geoWatcher  geoip.Watcher
}

// NewInfra dials authn, opens Redis, and constructs the abuse-protection
// drivers. External drivers (Turnstile, MaxMind) fall back to no-op/mock
// behaviour when not configured, so the gateway runs locally without secrets.
func NewInfra(_ context.Context, cfg Config) (*InfraDependencies, error) {
	if err := mtls.ValidatePathGroup(
		true,
		cfg.GRPCClientCertPath,
		cfg.GRPCClientKeyPath,
		cfg.GRPCRootCAPath,
	); err != nil {
		return nil, fmt.Errorf("gateway public outbound gRPC TLS: %w", err)
	}
	clientTLS, err := mtls.LoadClientTLSConfig(
		cfg.GRPCClientCertPath,
		cfg.GRPCClientKeyPath,
		cfg.GRPCRootCAPath,
	)
	if err != nil {
		return nil, fmt.Errorf("gateway public outbound gRPC TLS: %w", err)
	}
	redisKV := redis.NewRedisKVStore(cfg.RedisAddr, cfg.RedisDatabase)

	authnConn, err := grpcutils.DialTLSClient(cfg.AuthnGRPCAddr, clientTLS, grpcutils.DefaultClientResilienceConfig())
	if err != nil {
		errutil.CloseIf(redisKV)
		return nil, fmt.Errorf("authn grpc dial: %w", err)
	}

	authzConn, err := grpcutils.DialTLSClient(cfg.AuthzGRPCAddr, clientTLS, grpcutils.DefaultClientResilienceConfig())
	if err != nil {
		errutil.CloseIf(authnConn)
		errutil.CloseIf(redisKV)
		return nil, fmt.Errorf("authz grpc dial: %w", err)
	}

	profileConn, err := grpcutils.DialTLSClient(cfg.ProfileGRPCAddr, clientTLS, grpcutils.DefaultClientResilienceConfig())
	if err != nil {
		errutil.CloseIf(authzConn)
		errutil.CloseIf(authnConn)
		errutil.CloseIf(redisKV)
		return nil, fmt.Errorf("profile grpc dial: %w", err)
	}

	signingKeyClient := authnpb.NewSigningKeyServiceClient(authnConn)

	deps := &InfraDependencies{
		GlobalConfig:         cfg,
		Redis:                redisKV,
		OIDCClient:           authnpb.NewOIDCServiceClient(authnConn),
		AuthFlowClient:       authnpb.NewAuthenticationFlowServiceClient(authnConn),
		SessionClient:        authnpb.NewSessionServiceClient(authnConn),
		LinkedIdentityClient: authnpb.NewLinkedIdentityServiceClient(authnConn),
		SigningKeyClient:     signingKeyClient,
		// authn hosts the JWKS (GetPublicKeys); reuse its connection to verify
		// session access-token JWTs locally at the edge.
		Verifier: jwtauth.NewAuthnVerifier(
			signingKeyClient,
			cfg.SessionAccessTokenIssuer,
			time.Duration(cfg.JWKSCacheTTLSeconds)*time.Second,
		),
		AuthzUserClient:  authzpb.NewAuthzUserServiceClient(authzConn),
		AuthzOrgClient:   authzpb.NewAuthzOrganizationAdminServiceClient(authzConn),
		ProfileClient:    profilepb.NewProfileServiceClient(profileConn),
		OrgProfileClient: profilepb.NewOrganizationProfileServiceClient(profileConn),
		authnConn:        authnConn,
		authzConn:        authzConn,
		profileConn:      profileConn,
	}

	// Turnstile: real verifier when a secret is set; the permissive mock is only
	// allowed in debug (Validate requires the secret in production).
	switch {
	case strings.TrimSpace(cfg.TurnstileSecret) != "":
		verifier, err := turnstile.New(turnstile.Config{SecretKey: cfg.TurnstileSecret})
		if err != nil {
			deps.Close()
			return nil, fmt.Errorf("turnstile: %w", err)
		}
		deps.Turnstile = verifier
	case cfg.Debug:
		deps.Turnstile = turnstile.AlwaysValid()
	default:
		deps.Close()
		return nil, fmt.Errorf("turnstile secret is required in production")
	}

	// GeoIP: open + watch the mmdb when a path is configured.
	if path := strings.TrimSpace(cfg.GeoIPPath); path != "" {
		resolver, err := geoip.Open(geoip.Config{
			Path:           path,
			ReloadInterval: time.Duration(cfg.GeoIPReloadSeconds) * time.Second,
		})
		if err != nil {
			deps.Close()
			return nil, fmt.Errorf("geoip open: %w", err)
		}
		deps.Geo = resolver
		deps.geoWatcher = resolver
	} else {
		log.Printf("gateway-public: GEOIP_PATH unset, IP geolocation disabled")
		deps.Geo = geoip.NewMockResolver(geoip.GeoInfo{})
	}

	// CSRF: enabled only when a signing secret is provided.
	if secret := strings.TrimSpace(cfg.CSRFSecret); secret != "" {
		manager, err := csrf.New([]byte(secret), time.Duration(cfg.CSRFTTLSeconds)*time.Second)
		if err != nil {
			deps.Close()
			return nil, fmt.Errorf("csrf: %w", err)
		}
		deps.CSRF = manager
	}

	// Trusted-documents allowlist. Outside debug mode the gateway only runs
	// pre-registered operations, so an empty manifest is a misconfiguration that
	// would reject every request — fail fast.
	ops, err := persisted.Load(strings.TrimSpace(cfg.PersistedOpsPath))
	if err != nil {
		deps.Close()
		return nil, fmt.Errorf("persisted operations: %w", err)
	}
	if !cfg.Debug && len(ops) == 0 {
		deps.Close()
		return nil, fmt.Errorf("persisted operations: %w (set GATEWAY_PUBLIC_PERSISTED_OPS_PATH or enable DEBUG)", persisted.ErrEmptyManifest)
	}
	deps.PersistedOps = ops

	return deps, nil
}

// StartBackground launches the GeoIP reload watcher (no-op when GeoIP disabled).
func (d *InfraDependencies) StartBackground(ctx context.Context) {
	if d.geoWatcher != nil {
		d.geoWatcher.StartWatch(ctx)
	}
}

// Close releases all owned resources.
func (d *InfraDependencies) Close() error {
	errutil.CloseIf(d.Geo)
	errutil.CloseIf(d.authnConn)
	errutil.CloseIf(d.authzConn)
	errutil.CloseIf(d.profileConn)
	errutil.CloseIf(d.Redis)
	return nil
}
