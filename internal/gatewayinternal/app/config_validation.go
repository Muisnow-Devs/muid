package app

import (
	"fmt"
	"os"
	"strings"

	"github.com/google/uuid"

	"sanzi.io/muid/pkg/shared"
)

// Validate checks the internal gateway configuration for required production
// settings. Debug mode relaxes only the explicit production environment checks;
// the admin allowlist and semantic safety checks always apply.
func (cfg Config) Validate() error {
	return cfg.validate(os.LookupEnv)
}

func (cfg Config) validate(lookup shared.EnvLookup) error {
	err := shared.ValidateRequiredEnvInProduction(cfg.Debug, "GATEWAY_INTERNAL_DEBUG", lookup, []string{
		"GATEWAY_INTERNAL_TRUST_FORWARD_HEADER",
		"GATEWAY_INTERNAL_ADMIN_USER_IDS",
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
	return validateAdminUserIDs(cfg.AdminUserIDs)
}

func validateAdminUserIDs(values []string) error {
	if len(values) == 0 {
		return fmt.Errorf("gateway internal ADMIN_USER_IDS must not be empty")
	}
	seen := make(map[uuid.UUID]struct{}, len(values))
	for _, value := range values {
		id, err := uuid.Parse(strings.TrimSpace(value))
		if err != nil || id == uuid.Nil {
			return fmt.Errorf("gateway internal ADMIN_USER_IDS contains invalid UUID %q", value)
		}
		if _, ok := seen[id]; ok {
			return fmt.Errorf("gateway internal ADMIN_USER_IDS contains duplicate UUID %q", value)
		}
		seen[id] = struct{}{}
	}
	return nil
}
