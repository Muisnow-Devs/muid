package app

import (
	"os"

	"sanzi.io/muid/pkg/shared"
)

// Validate checks the services gateway configuration for required production
// settings. In debug mode the checks are skipped so the gateway runs locally
// without mTLS.
func (cfg Config) Validate() error {
	return cfg.validate(os.LookupEnv)
}

func (cfg Config) validate(lookup shared.EnvLookup) error {
	return shared.ValidateRequiredEnvInProduction(cfg.Debug, "GATEWAY_SERVICES_DEBUG", lookup, []string{
		"GATEWAY_SERVICES_MTLS_CLIENT_CA_PATH",
		"GATEWAY_SERVICES_TLS_CERT_PATH",
		"GATEWAY_SERVICES_TLS_KEY_PATH",
		"GATEWAY_SERVICES_TRUST_FORWARD_HEADER",
	})
}
