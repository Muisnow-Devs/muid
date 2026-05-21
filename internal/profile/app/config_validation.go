package app

import (
	"os"

	"sanzi.io/muid/pkg/shared"
)

func (cfg Config) Validate() error {
	return cfg.validate(os.LookupEnv)
}

func (cfg Config) validate(lookup shared.EnvLookup) error {
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
