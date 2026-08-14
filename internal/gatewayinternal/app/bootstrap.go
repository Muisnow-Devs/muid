package app

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	"google.golang.org/grpc"

	authnpb "sanzi.io/muid/api/proto/authn/v1"
	authzpb "sanzi.io/muid/api/proto/authz/v1"
	"sanzi.io/muid/infra/redis"
	"sanzi.io/muid/pkg/authzclient"
	"sanzi.io/muid/pkg/errutil"
	"sanzi.io/muid/pkg/gateway/jwtauth"
	grpcutils "sanzi.io/muid/pkg/grpc_utils"
	"sanzi.io/muid/pkg/mtls"
	"sanzi.io/muid/pkg/shared/kv"
)

// InfraDependencies holds the internal gateway's wired infrastructure.
type InfraDependencies struct {
	GlobalConfig Config

	Redis         kv.AtomicKVStore
	Verifier      *jwtauth.Verifier
	OIDCAdmin     authnpb.OIDCClientAdminServiceClient
	AuthzAdmin    authzpb.AuthzAdminServiceClient
	PlatformAuthz platformPermissionChecker
	TLSConfig     *tls.Config

	authnConn *grpc.ClientConn
	authzConn *grpc.ClientConn
}

// NewInfra dials the authn + authz internal admin surfaces, opens Redis, and
// builds the admin JWT verifier (JWKS sourced from authn).
func NewInfra(_ context.Context, cfg Config) (*InfraDependencies, error) {
	serverTLS, err := buildAdminIngressTLS(cfg)
	if err != nil {
		return nil, err
	}
	if err := mtls.ValidatePathGroup(
		true,
		cfg.GRPCClientCertPath,
		cfg.GRPCClientKeyPath,
		cfg.GRPCRootCAPath,
	); err != nil {
		return nil, fmt.Errorf("gateway internal outbound gRPC TLS: %w", err)
	}
	clientTLS, err := mtls.LoadClientTLSConfig(
		cfg.GRPCClientCertPath,
		cfg.GRPCClientKeyPath,
		cfg.GRPCRootCAPath,
	)
	if err != nil {
		return nil, fmt.Errorf("gateway internal outbound gRPC TLS: %w", err)
	}
	redisKV := redis.NewRedisKVStore(cfg.RedisAddr, cfg.RedisDatabase)

	authnConn, err := grpcutils.DialTLSClient(cfg.AuthnGRPCAddr, clientTLS, grpcutils.DefaultClientResilienceConfig())
	if err != nil {
		errutil.CloseIf(redisKV)
		return nil, fmt.Errorf("authn grpc dial: %w", err)
	}

	authzConn, err := grpcutils.DialTLSClient(cfg.AuthzInternalGRPCAddr, clientTLS, grpcutils.DefaultClientResilienceConfig())
	if err != nil {
		errutil.CloseIf(authnConn)
		errutil.CloseIf(redisKV)
		return nil, fmt.Errorf("authz grpc dial: %w", err)
	}

	verifier := jwtauth.NewAuthnVerifier(
		authnpb.NewSigningKeyServiceClient(authnConn),
		cfg.SessionAccessTokenIssuer,
		time.Duration(cfg.JWKSCacheTTLSeconds)*time.Second,
	)
	authzClient := authzpb.NewAuthzServiceClient(authzConn)
	platformAuthz, err := authzclient.NewPlatformChecker(authzClient)
	if err != nil {
		errutil.CloseIf(authzConn)
		errutil.CloseIf(authnConn)
		errutil.CloseIf(redisKV)
		return nil, fmt.Errorf("platform authz client: %w", err)
	}

	return &InfraDependencies{
		GlobalConfig:  cfg,
		Redis:         redisKV,
		Verifier:      verifier,
		OIDCAdmin:     authnpb.NewOIDCClientAdminServiceClient(authnConn),
		AuthzAdmin:    authzpb.NewAuthzAdminServiceClient(authzConn),
		PlatformAuthz: platformAuthz,
		TLSConfig:     serverTLS,
		authnConn:     authnConn,
		authzConn:     authzConn,
	}, nil
}

func buildAdminIngressTLS(cfg Config) (*tls.Config, error) {
	if err := mtls.ValidatePathGroup(
		true,
		cfg.MTLSClientCAPath,
		cfg.TLSCertPath,
		cfg.TLSKeyPath,
	); err != nil {
		return nil, fmt.Errorf("gateway internal ingress mTLS: %w", err)
	}
	serverTLS, err := mtls.LoadServerTLSConfig(
		cfg.TLSCertPath,
		cfg.TLSKeyPath,
		cfg.MTLSClientCAPath,
	)
	if err != nil {
		return nil, fmt.Errorf("gateway internal ingress mTLS: %w", err)
	}
	return requireAdminIngressWorkload(serverTLS), nil
}

func requireAdminIngressWorkload(config *tls.Config) *tls.Config {
	verify := func(state tls.ConnectionState) error {
		workload, ok := grpcutils.VerifiedWorkloadFromTLSState(state)
		if !ok || workload != grpcutils.WorkloadAdminIngress {
			return fmt.Errorf("gateway internal ingress: client workload is not permitted")
		}
		return nil
	}
	apply := func(selected *tls.Config) *tls.Config {
		clone := selected.Clone()
		previous := clone.VerifyConnection
		clone.VerifyConnection = func(state tls.ConnectionState) error {
			if previous != nil {
				if err := previous(state); err != nil {
					return err
				}
			}
			return verify(state)
		}
		return clone
	}

	wrapped := apply(config)
	selectConfig := config.GetConfigForClient
	if selectConfig == nil {
		return wrapped
	}
	wrapped.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		selected, err := selectConfig(hello)
		if err != nil {
			return nil, err
		}
		if selected == nil {
			selected = config
		}
		selected = apply(selected)
		selected.GetConfigForClient = nil
		return selected, nil
	}
	return wrapped
}

// Close releases all owned resources.
func (d *InfraDependencies) Close() error {
	errutil.CloseIf(d.authnConn)
	errutil.CloseIf(d.authzConn)
	errutil.CloseIf(d.Redis)
	return nil
}
