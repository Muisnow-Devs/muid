package app

import (
	"fmt"
	"os"
	"strings"

	"sanzi.io/muid/pkg/mtls"
	"sanzi.io/muid/pkg/shared"
)

// Validate checks the internal gateway configuration for required production
// settings. Ingress and backend mTLS are required in every mode; Authz owns
// administrator authority rather than a gateway-local allowlist.
func (cfg Config) Validate() error {
	return cfg.validate(os.LookupEnv)
}

func (cfg Config) validate(lookup shared.EnvLookup) error {
	err := shared.ValidateRequiredEnvInProduction(cfg.Debug, "GATEWAY_INTERNAL_DEBUG", lookup, []string{
		"GATEWAY_INTERNAL_TRUST_FORWARD_HEADER",
	})
	if err != nil {
		return err
	}
	return cfg.validateValues()
}

func (cfg Config) validateValues() error {
	if err := mtls.ValidatePathGroup(
		true,
		cfg.MTLSClientCAPath,
		cfg.TLSCertPath,
		cfg.TLSKeyPath,
	); err != nil {
		return fmt.Errorf("gateway internal ingress mTLS configuration: %w", err)
	}
	if err := mtls.ValidatePathGroup(
		true,
		cfg.GRPCClientCertPath,
		cfg.GRPCClientKeyPath,
		cfg.GRPCRootCAPath,
	); err != nil {
		return fmt.Errorf("gateway internal outbound gRPC TLS configuration: %w", err)
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{name: "AUTHN_GRPC_ADDR", value: cfg.AuthnGRPCAddr},
		{name: "AUTHZ_INTERNAL_GRPC_ADDR", value: cfg.AuthzInternalGRPCAddr},
		{name: "REDIS_ADDR", value: cfg.RedisAddr},
		{name: "SESSION_ACCESS_TOKEN_ISSUER", value: cfg.SessionAccessTokenIssuer},
	} {
		if strings.TrimSpace(field.value) == "" {
			return fmt.Errorf("gateway internal %s must not be empty", field.name)
		}
	}
	if cfg.Port < 1 || cfg.Port > 65535 {
		return fmt.Errorf("gateway internal PORT must be between 1 and 65535")
	}
	if cfg.RedisDatabase < 0 {
		return fmt.Errorf("gateway internal REDIS_DATABASE must not be negative")
	}
	if cfg.RateLimit < 0 {
		return fmt.Errorf("gateway internal RATE_LIMIT must not be negative")
	}
	if !cfg.Debug && cfg.RateLimit == 0 {
		return fmt.Errorf("gateway internal RATE_LIMIT must be positive in production")
	}
	if cfg.JWKSCacheTTLSeconds <= 0 || cfg.RateLimitWindowSeconds <= 0 || cfg.RequestTimeoutSeconds <= 0 {
		return fmt.Errorf("gateway internal TTL, rate-limit window, and request timeout values must be positive")
	}
	if cfg.RiskPoWThreshold <= 0 || cfg.RiskPoWThreshold >= cfg.RiskBlockThreshold || cfg.RiskBlockThreshold > 100 {
		return fmt.Errorf("gateway internal risk thresholds must satisfy 0 < PoW < block <= 100")
	}
	if cfg.TrustForwardHeader && strings.TrimSpace(cfg.RealIPHeader) == "" {
		return fmt.Errorf("gateway internal REAL_IP_HEADER must not be empty when forwarding headers are trusted")
	}
	return nil
}
