package app

import (
	"fmt"
	"os"
	"strings"

	"sanzi.io/muid/pkg/mtls"
	"sanzi.io/muid/pkg/shared"
)

func (cfg Config) Validate() error {
	return cfg.validate(os.LookupEnv)
}

func (cfg Config) validate(lookup shared.EnvLookup) error {
	if strings.TrimSpace(cfg.DatabaseURL) == "" {
		return fmt.Errorf("profile: DATABASE_URL is required")
	}
	if strings.TrimSpace(cfg.NATSURL) == "" {
		return fmt.Errorf("profile: NATS_URL is required")
	}
	if cfg.Port < 1 || cfg.Port > 65535 {
		return fmt.Errorf("profile: PORT must be between 1 and 65535")
	}
	if cfg.RequestTimeoutSeconds <= 0 {
		return fmt.Errorf("profile: REQUEST_TIMEOUT_SECONDS must be positive")
	}
	if cfg.AuthzRoleCacheTTLSeconds < 0 {
		return fmt.Errorf("profile: AUTHZ_ROLE_CACHE_TTL_SECONDS must be nonnegative")
	}
	if cfg.AuthzPolicyRefreshSeconds < 0 {
		return fmt.Errorf("profile: AUTHZ_POLICY_REFRESH_SECONDS must be nonnegative")
	}
	if err := mtls.ValidatePathGroup(
		!cfg.Debug,
		cfg.GRPCTLSCertPath,
		cfg.GRPCTLSKeyPath,
		cfg.GRPCMTLSClientCAPath,
	); err != nil {
		return fmt.Errorf("profile: inbound gRPC TLS configuration: %w", err)
	}
	if err := mtls.ValidatePathGroup(
		!cfg.Debug,
		cfg.GRPCClientCertPath,
		cfg.GRPCClientKeyPath,
		cfg.GRPCRootCAPath,
	); err != nil {
		return fmt.Errorf("profile: outbound gRPC TLS configuration: %w", err)
	}

	required := []string{
		"PROFILE_DATABASE_URL",
		"PROFILE_NATS_URL",
	}
	if profileR2Configured(cfg) {
		required = append(required, "PROFILE_PUBLIC_ASSETS_URL")
	}
	return shared.ValidateRequiredEnvInProduction(cfg.Debug, "PROFILE_DEBUG", lookup, required)
}

func profileR2Configured(cfg Config) bool {
	return cfg.R2AccountID != "" ||
		cfg.R2AccessKeyID != "" ||
		cfg.R2SecretAccessKey != "" ||
		cfg.R2UploadBucket != "" ||
		cfg.R2AssetsBucket != ""
}
