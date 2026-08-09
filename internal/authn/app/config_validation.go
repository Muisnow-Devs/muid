package app

import (
	"fmt"
	"os"

	"sanzi.io/muid/pkg/mtls"
	"sanzi.io/muid/pkg/shared"
)

// Validate checks the authn configuration for required production settings.
func (cfg Config) Validate() error {
	return cfg.validate(os.LookupEnv)
}

func (cfg Config) validate(lookup shared.EnvLookup) error {
	if err := mtls.ValidatePathGroup(
		true,
		cfg.GRPCTLSCertPath,
		cfg.GRPCTLSKeyPath,
		cfg.GRPCMTLSClientCAPath,
	); err != nil {
		return fmt.Errorf("authn: inbound gRPC TLS configuration: %w", err)
	}
	if err := mtls.ValidatePathGroup(
		true,
		cfg.GRPCClientCertPath,
		cfg.GRPCClientKeyPath,
		cfg.GRPCRootCAPath,
	); err != nil {
		return fmt.Errorf("authn: outbound gRPC TLS configuration: %w", err)
	}
	return shared.ValidateRequiredEnvInProduction(cfg.Debug, "AUTHN_DEBUG", lookup, []string{
		"AUTHN_DATABASE_URL",
		"AUTHN_REDIS_ADDR",
		"AUTHN_NATS_URL",
		"AUTHN_PROFILE_GRPC_ADDR",
		"AUTHN_PASSKEY_RP_ID",
		"AUTHN_PASSKEY_RP_ORIGINS",
	})
}
