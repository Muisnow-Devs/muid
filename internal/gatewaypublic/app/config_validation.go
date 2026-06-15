package app

import (
	"os"

	"sanzi.io/muid/pkg/shared"
)

// Validate checks the public gateway configuration for required production
// settings. In debug mode the checks are skipped so the gateway runs locally
// with permissive mocks/no-op security controls.
func (cfg Config) Validate() error {
	return cfg.validate(os.LookupEnv)
}

func (cfg Config) validate(lookup shared.EnvLookup) error {
	return shared.ValidateRequiredEnvInProduction(cfg.Debug, "GATEWAY_PUBLIC_DEBUG", lookup, []string{
		"GATEWAY_PUBLIC_CSRF_SECRET",
		"GATEWAY_PUBLIC_TURNSTILE_SECRET",
		"GATEWAY_PUBLIC_CORS_ALLOWED_ORIGINS",
		"GATEWAY_PUBLIC_TRUST_FORWARD_HEADER",
		"GATEWAY_PUBLIC_PERSISTED_OPS_PATH",
	})
}
