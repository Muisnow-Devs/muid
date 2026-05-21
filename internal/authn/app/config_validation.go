package app

import (
	"os"

	"sanzi.io/muid/pkg/shared"
)

func (cfg Config) Validate() error {
	return cfg.validate(os.LookupEnv)
}

func (cfg Config) validate(lookup shared.EnvLookup) error {
	return shared.ValidateRequiredEnvInProduction(cfg.Debug, "AUTHN_DEBUG", lookup, []string{
		"AUTHN_DATABASE_URL",
		"AUTHN_REDIS_URL",
		"AUTHN_NATS_URL",
		"AUTHN_PROFILE_GRPC_ADDR",
		"AUTHN_PASSKEY_RP_ID",
		"AUTHN_PASSKEY_RP_ORIGINS",
	})
}
