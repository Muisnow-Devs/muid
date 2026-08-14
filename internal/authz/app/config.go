package app

import (
	"fmt"
	"strings"

	"google.golang.org/grpc"

	profilepb "sanzi.io/muid/api/proto/profile/v1"
	authzent "sanzi.io/muid/internal/authz/ent"
	"sanzi.io/muid/internal/authz/policy"
	"sanzi.io/muid/pkg/errutil"
	"sanzi.io/muid/pkg/mtls"
	"sanzi.io/muid/pkg/shared/pubsub"
)

const ConfigEnvPrefix = "AUTHZ"

type Config struct {
	Debug bool `envconfig:"DEBUG" default:"false"`

	// Port serves the public surface (AuthzUserService +
	// AuthzOrganizationAdminService) behind the gateway; InternalPort serves
	// the internal surface (AuthzService + AuthzAdminService) and must never
	// be reachable through the gateway.
	Port         int    `envconfig:"PORT"          default:"5315"`
	InternalPort int    `envconfig:"INTERNAL_PORT" default:"5316"`
	DatabaseURL  string `envconfig:"DATABASE_URL"                 required:"true"`
	NATSURL      string `envconfig:"NATS_URL"                     required:"true"`

	// PolicyConfigPath (a JSON file) wins over PolicyConfigJSON (inline);
	// with neither set the embedded default policy applies.
	PolicyConfigPath string `envconfig:"POLICY_CONFIG_PATH"`
	PolicyConfigJSON string `envconfig:"POLICY_CONFIG_JSON"`

	// PolicyReloadSeconds is the periodic full policy reload from storage
	// (drift safety net for missed events); 0 disables it.
	PolicyReloadSeconds int `envconfig:"POLICY_RELOAD_SECONDS" default:"300"`

	// ProfileGRPCAddr is the profile service address used to provision an
	// organization's profile (slug/display name/description) on creation.
	// Empty disables that step (the org is still created).
	ProfileGRPCAddr string `envconfig:"PROFILE_GRPC_ADDR"`

	RequestTimeoutSeconds int `envconfig:"REQUEST_TIMEOUT_SECONDS" default:"10"`

	GRPCTLSCertPath      string `envconfig:"GRPC_TLS_CERT_PATH"`
	GRPCTLSKeyPath       string `envconfig:"GRPC_TLS_KEY_PATH"`
	GRPCMTLSClientCAPath string `envconfig:"GRPC_MTLS_CLIENT_CA_PATH"`

	GRPCClientCertPath string `envconfig:"GRPC_CLIENT_CERT_PATH"`
	GRPCClientKeyPath  string `envconfig:"GRPC_CLIENT_KEY_PATH"`
	GRPCRootCAPath     string `envconfig:"GRPC_ROOT_CA_PATH"`
}

func (c Config) Validate() error {
	if strings.TrimSpace(c.DatabaseURL) == "" {
		return fmt.Errorf("authz: DATABASE_URL is required")
	}
	if strings.TrimSpace(c.NATSURL) == "" {
		return fmt.Errorf("authz: NATS_URL is required")
	}
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("authz: PORT must be between 1 and 65535")
	}
	if c.InternalPort < 1 || c.InternalPort > 65535 {
		return fmt.Errorf("authz: INTERNAL_PORT must be between 1 and 65535")
	}
	if c.Port == c.InternalPort {
		return fmt.Errorf("authz: PORT and INTERNAL_PORT must differ")
	}
	if c.PolicyReloadSeconds < 0 {
		return fmt.Errorf("authz: POLICY_RELOAD_SECONDS must be nonnegative")
	}
	if c.RequestTimeoutSeconds <= 0 {
		return fmt.Errorf("authz: REQUEST_TIMEOUT_SECONDS must be positive")
	}
	if err := validateTLSPathGroup(
		"GRPC_TLS_CERT_PATH, GRPC_TLS_KEY_PATH and GRPC_MTLS_CLIENT_CA_PATH",
		true,
		c.GRPCTLSCertPath,
		c.GRPCTLSKeyPath,
		c.GRPCMTLSClientCAPath,
	); err != nil {
		return err
	}
	return validateTLSPathGroup(
		"GRPC_CLIENT_CERT_PATH, GRPC_CLIENT_KEY_PATH and GRPC_ROOT_CA_PATH",
		true,
		c.GRPCClientCertPath,
		c.GRPCClientKeyPath,
		c.GRPCRootCAPath,
	)
}

func validateTLSPathGroup(name string, required bool, values ...string) error {
	if err := mtls.ValidatePathGroup(required, values...); err != nil {
		return fmt.Errorf("authz: %s: %w", name, err)
	}
	return nil
}

type InfraDependencies struct {
	GlobalConfig Config

	entClient     *authzent.Client
	pubSub        pubsub.PubSub
	PolicyManager *policy.Manager

	profileConn   *grpc.ClientConn
	ProfileClient profilepb.OrganizationProfileServiceClient
}

func (d *InfraDependencies) Close() error {
	if d.PolicyManager != nil {
		errutil.Discard(d.PolicyManager.Close())
	}
	errutil.CloseIf(d.profileConn)
	errutil.CloseIf(d.pubSub)
	if d.entClient != nil {
		return d.entClient.Close()
	}
	return nil
}
