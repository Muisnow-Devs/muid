package app

import (
	"os"

	"sanzi.io/muid/pkg/shared"
)

// Validate checks the internal gateway configuration for required production
// settings. In debug mode the checks are skipped so the gateway runs locally
// without an admin allowlist.
func (cfg Config) Validate() error {
	return cfg.validate(os.LookupEnv)
}

func (cfg Config) validate(lookup shared.EnvLookup) error {
	return shared.ValidateRequiredEnvInProduction(cfg.Debug, "GATEWAY_INTERNAL_DEBUG", lookup, []string{
		"GATEWAY_INTERNAL_TRUST_FORWARD_HEADER",
		"GATEWAY_INTERNAL_ADMIN_USER_IDS",
	})
}
