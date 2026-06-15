package app

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"strings"
	"time"

	"google.golang.org/grpc"

	authnpb "sanzi.io/muid/api/proto/authn/v1"
	profilepb "sanzi.io/muid/api/proto/profile/v1"
	"sanzi.io/muid/infra/redis"
	"sanzi.io/muid/pkg/errutil"
	"sanzi.io/muid/pkg/gateway/jwtauth"
	"sanzi.io/muid/pkg/gateway/mtls"
	grpcutils "sanzi.io/muid/pkg/grpc_utils"
	"sanzi.io/muid/pkg/shared/kv"
)

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
// and constructs the mTLS server config when configured.
func NewInfra(_ context.Context, cfg Config) (*InfraDependencies, error) {
	redisKV := redis.NewRedisKVStore(cfg.RedisAddr, cfg.RedisDatabase)

	authnConn, err := grpcutils.DialInsecureClient(cfg.AuthnGRPCAddr, grpcutils.DefaultClientResilienceConfig())
	if err != nil {
		errutil.CloseIf(redisKV)
		return nil, fmt.Errorf("authn grpc dial: %w", err)
	}

	profileConn, err := grpcutils.DialInsecureClient(cfg.ProfileGRPCAddr, grpcutils.DefaultClientResilienceConfig())
	if err != nil {
		errutil.CloseIf(authnConn)
		errutil.CloseIf(redisKV)
		return nil, fmt.Errorf("profile grpc dial: %w", err)
	}

	verifier := jwtauth.NewAuthnVerifier(
		authnpb.NewAuthnServiceClient(authnConn),
		cfg.SessionAccessTokenIssuer,
		time.Duration(cfg.JWKSCacheTTLSeconds)*time.Second,
	)

	deps := &InfraDependencies{
		GlobalConfig: cfg,
		Redis:        redisKV,
		Verifier:     verifier,
		Profile:      profilepb.NewProfileServiceClient(profileConn),
		authnConn:    authnConn,
		profileConn:  profileConn,
	}

	tlsConfig, err := buildMTLS(cfg)
	if err != nil {
		deps.Close()
		return nil, err
	}
	if tlsConfig == nil && !cfg.Debug {
		deps.Close()
		return nil, fmt.Errorf("mtls: client-cert verification is required in production; set MTLS_CLIENT_CA_PATH, TLS_CERT_PATH and TLS_KEY_PATH (or DEBUG=true for local dev)")
	}
	deps.TLSConfig = tlsConfig

	return deps, nil
}

// buildMTLS returns a client-cert-verifying tls.Config, or nil when mTLS is not
// configured. Misconfiguration (partial settings) is an error.
func buildMTLS(cfg Config) (*tls.Config, error) {
	caPath := strings.TrimSpace(cfg.MTLSClientCAPath)
	certPath := strings.TrimSpace(cfg.TLSCertPath)
	keyPath := strings.TrimSpace(cfg.TLSKeyPath)
	if caPath == "" && certPath == "" && keyPath == "" {
		return nil, nil
	}
	if caPath == "" || certPath == "" || keyPath == "" {
		return nil, fmt.Errorf("mtls: MTLS_CLIENT_CA_PATH, TLS_CERT_PATH and TLS_KEY_PATH must all be set")
	}

	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("mtls: read client CA: %w", err)
	}
	roots, err := mtls.NewStaticRootsFromPEM(caPEM)
	if err != nil {
		return nil, fmt.Errorf("mtls: client CA: %w", err)
	}
	serverCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("mtls: load server cert: %w", err)
	}
	return mtls.ServerTLSConfig(roots, serverCert)
}

// Close releases all owned resources.
func (d *InfraDependencies) Close() error {
	errutil.CloseIf(d.authnConn)
	errutil.CloseIf(d.profileConn)
	errutil.CloseIf(d.Redis)
	return nil
}
