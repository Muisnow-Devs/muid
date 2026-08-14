package app

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	"google.golang.org/grpc"

	authnpb "sanzi.io/muid/api/proto/authn/v1"
	profilepb "sanzi.io/muid/api/proto/profile/v1"
	"sanzi.io/muid/infra/redis"
	"sanzi.io/muid/pkg/errutil"
	"sanzi.io/muid/pkg/gateway/jwtauth"
	grpcutils "sanzi.io/muid/pkg/grpc_utils"
	"sanzi.io/muid/pkg/mtls"
	"sanzi.io/muid/pkg/shared/kv"
)

const requiredSessionAudience = "gateway-services"

// InfraDependencies holds the services gateway's wired infrastructure.
type InfraDependencies struct {
	GlobalConfig Config

	Redis     kv.AtomicKVStore
	Verifier  *jwtauth.Verifier
	Profile   profilepb.ProfileServiceClient
	TLSConfig *tls.Config // nil unless mTLS is configured

	authnConn   *grpc.ClientConn
	profileConn *grpc.ClientConn
}

// NewInfra dials authn (JWKS) + profile, opens Redis, builds the JWT verifier,
// and constructs the mandatory ingress and backend mTLS configurations.
func NewInfra(_ context.Context, cfg Config) (*InfraDependencies, error) {
	tlsConfig, err := buildMTLS(cfg)
	if err != nil {
		return nil, err
	}
	if err := mtls.ValidatePathGroup(
		true,
		cfg.GRPCClientCertPath,
		cfg.GRPCClientKeyPath,
		cfg.GRPCRootCAPath,
	); err != nil {
		return nil, fmt.Errorf("gateway services outbound gRPC TLS: %w", err)
	}
	clientTLS, err := mtls.LoadClientTLSConfig(
		cfg.GRPCClientCertPath,
		cfg.GRPCClientKeyPath,
		cfg.GRPCRootCAPath,
	)
	if err != nil {
		return nil, fmt.Errorf("gateway services outbound gRPC TLS: %w", err)
	}
	redisKV := redis.NewRedisKVStore(cfg.RedisAddr, cfg.RedisDatabase)

	authnConn, err := grpcutils.DialTLSClient(cfg.AuthnGRPCAddr, clientTLS, grpcutils.DefaultClientResilienceConfig())
	if err != nil {
		errutil.CloseIf(redisKV)
		return nil, fmt.Errorf("authn grpc dial: %w", err)
	}

	profileConn, err := grpcutils.DialTLSClient(cfg.ProfileGRPCAddr, clientTLS, grpcutils.DefaultClientResilienceConfig())
	if err != nil {
		errutil.CloseIf(authnConn)
		errutil.CloseIf(redisKV)
		return nil, fmt.Errorf("profile grpc dial: %w", err)
	}

	verifier := jwtauth.NewAuthnVerifierWithConfig(
		authnpb.NewSigningKeyServiceClient(authnConn),
		jwtauth.Config{
			Issuer:           cfg.SessionAccessTokenIssuer,
			RequiredAudience: requiredSessionAudience,
			CacheTTL:         time.Duration(cfg.JWKSCacheTTLSeconds) * time.Second,
		},
	)

	deps := &InfraDependencies{
		GlobalConfig: cfg,
		Redis:        redisKV,
		Verifier:     verifier,
		Profile:      profilepb.NewProfileServiceClient(profileConn),
		TLSConfig:    tlsConfig,
		authnConn:    authnConn,
		profileConn:  profileConn,
	}

	return deps, nil
}

// buildMTLS returns the mandatory client-cert-verifying listener config.
func buildMTLS(cfg Config) (*tls.Config, error) {
	if err := mtls.ValidatePathGroup(
		true,
		cfg.MTLSClientCAPath,
		cfg.TLSCertPath,
		cfg.TLSKeyPath,
	); err != nil {
		return nil, fmt.Errorf("gateway services ingress mTLS: %w", err)
	}
	tlsConfig, err := mtls.LoadServerTLSConfig(
		cfg.TLSCertPath,
		cfg.TLSKeyPath,
		cfg.MTLSClientCAPath,
	)
	if err != nil {
		return nil, fmt.Errorf("gateway services ingress mTLS: %w", err)
	}
	return tlsConfig, nil
}

// Close releases all owned resources.
func (d *InfraDependencies) Close() error {
	errutil.CloseIf(d.authnConn)
	errutil.CloseIf(d.profileConn)
	errutil.CloseIf(d.Redis)
	return nil
}
