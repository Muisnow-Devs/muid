package app

import (
	"os"

	"sanzi.io/muid/pkg/shared"
)

func (cfg Config) Validate() error {
	return cfg.validate(os.LookupEnv)
}

func (cfg Config) validate(lookup shared.EnvLookup) error {
	return shared.ValidateRequiredEnvInProduction(cfg.Debug, "MAILER_DEBUG", lookup, []string{
		"MAILER_NATS_URL",
		"MAILER_SMTP_HOST",
		"MAILER_SMTP_FROM",
	})
}
