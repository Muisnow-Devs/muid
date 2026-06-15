package app

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/grpc"

	authnpb "sanzi.io/muid/api/proto/authn/v1"
	authzpb "sanzi.io/muid/api/proto/authz/v1"
	"sanzi.io/muid/infra/redis"
	"sanzi.io/muid/pkg/errutil"
	"sanzi.io/muid/pkg/gateway/jwtauth"
	grpcutils "sanzi.io/muid/pkg/grpc_utils"
	"sanzi.io/muid/pkg/shared/kv"
)

// InfraDependencies holds the internal gateway's wired infrastructure.
type InfraDependencies struct {
	GlobalConfig Config

	Redis      kv.AtomicKVStore
	Verifier   *jwtauth.Verifier
	OIDCAdmin  authnpb.OIDCClientAdminServiceClient
	AuthzAdmin authzpb.AuthzAdminServiceClient

	authnConn *grpc.ClientConn
	authzConn *grpc.ClientConn
}

// NewInfra dials the authn + authz internal admin surfaces, opens Redis, and
// builds the admin JWT verifier (JWKS sourced from authn).
func NewInfra(_ context.Context, cfg Config) (*InfraDependencies, error) {
	redisKV := redis.NewRedisKVStore(cfg.RedisAddr, cfg.RedisDatabase)

	authnConn, err := grpcutils.DialInsecureClient(cfg.AuthnGRPCAddr, grpcutils.DefaultClientResilienceConfig())
	if err != nil {
		errutil.CloseIf(redisKV)
		return nil, fmt.Errorf("authn grpc dial: %w", err)
	}

	authzConn, err := grpcutils.DialInsecureClient(cfg.AuthzInternalGRPCAddr, grpcutils.DefaultClientResilienceConfig())
	if err != nil {
		errutil.CloseIf(authnConn)
		errutil.CloseIf(redisKV)
		return nil, fmt.Errorf("authz grpc dial: %w", err)
	}

	verifier := jwtauth.NewAuthnVerifier(
		authnpb.NewAuthnServiceClient(authnConn),
		cfg.SessionAccessTokenIssuer,
		time.Duration(cfg.JWKSCacheTTLSeconds)*time.Second,
	)

	return &InfraDependencies{
		GlobalConfig: cfg,
		Redis:        redisKV,
		Verifier:     verifier,
		OIDCAdmin:    authnpb.NewOIDCClientAdminServiceClient(authnConn),
		AuthzAdmin:   authzpb.NewAuthzAdminServiceClient(authzConn),
		authnConn:    authnConn,
		authzConn:    authzConn,
	}, nil
}

// Close releases all owned resources.
func (d *InfraDependencies) Close() error {
	errutil.CloseIf(d.authnConn)
	errutil.CloseIf(d.authzConn)
	errutil.CloseIf(d.Redis)
	return nil
}
