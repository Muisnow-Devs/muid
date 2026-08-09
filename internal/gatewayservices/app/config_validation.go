package app

import (
	"fmt"
	"os"
	"strings"

	"sanzi.io/muid/pkg/shared"
)

// Validate checks the services gateway configuration for required production
// settings. In debug mode the checks are skipped so the gateway runs locally
// without mTLS.
func (cfg Config) Validate() error {
	return cfg.validate(os.LookupEnv)
}

func (cfg Config) validate(lookup shared.EnvLookup) error {
	err := shared.ValidateRequiredEnvInProduction(cfg.Debug, "GATEWAY_SERVICES_DEBUG", lookup, []string{
		"GATEWAY_SERVICES_MTLS_CLIENT_CA_PATH",
		"GATEWAY_SERVICES_TLS_CERT_PATH",
		"GATEWAY_SERVICES_TLS_KEY_PATH",
		"GATEWAY_SERVICES_TRUST_FORWARD_HEADER",
	})
	if err != nil {
		return err
	}
	return cfg.validateValues()
}

func (cfg Config) validateValues() error {
	for _, field := range []struct {
		name  string
		value string
	}{
		{name: "AUTHN_GRPC_ADDR", value: cfg.AuthnGRPCAddr},
		{name: "PROFILE_GRPC_ADDR", value: cfg.ProfileGRPCAddr},
		{name: "REDIS_ADDR", value: cfg.RedisAddr},
		{name: "SESSION_ACCESS_TOKEN_ISSUER", value: cfg.SessionAccessTokenIssuer},
	} {
		if strings.TrimSpace(field.value) == "" {
			return fmt.Errorf("gateway services %s must not be empty", field.name)
		}
	}
	if cfg.Port < 1 || cfg.Port > 65535 {
		return fmt.Errorf("gateway services PORT must be between 1 and 65535")
	}
	if cfg.RedisDatabase < 0 {
		return fmt.Errorf("gateway services REDIS_DATABASE must not be negative")
	}
	if cfg.RateLimit < 0 {
		return fmt.Errorf("gateway services RATE_LIMIT must not be negative")
	}
	if !cfg.Debug && cfg.RateLimit == 0 {
		return fmt.Errorf("gateway services RATE_LIMIT must be positive in production")
	}
	if cfg.JWKSCacheTTLSeconds <= 0 || cfg.RateLimitWindowSeconds <= 0 || cfg.RequestTimeoutSeconds <= 0 {
		return fmt.Errorf("gateway services TTL, rate-limit window, and request timeout values must be positive")
	}
	configured := 0
	for _, value := range []string{cfg.MTLSClientCAPath, cfg.TLSCertPath, cfg.TLSKeyPath} {
		if strings.TrimSpace(value) != "" {
			configured++
		}
	}
	if configured != 0 && configured != 3 {
		return fmt.Errorf("gateway services mTLS client CA, certificate, and key must be configured together")
	}
	if !cfg.Debug && configured != 3 {
		return fmt.Errorf("gateway services mTLS client CA, certificate, and key must not be empty in production")
	}
	return nil
}
