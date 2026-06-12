package app

import (
	authzent "sanzi.io/muid/internal/authz/ent"
	"sanzi.io/muid/internal/authz/policy"
	"sanzi.io/muid/pkg/errutil"
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

	RequestTimeoutSeconds int `envconfig:"REQUEST_TIMEOUT_SECONDS" default:"10"`
}

type InfraDependencies struct {
	GlobalConfig Config

	entClient     *authzent.Client
	pubSub        pubsub.PubSub
	PolicyManager *policy.Manager
}

func (d *InfraDependencies) Close() error {
	if d.PolicyManager != nil {
		errutil.Discard(d.PolicyManager.Close())
	}
	errutil.CloseIf(d.pubSub)
	if d.entClient != nil {
		return d.entClient.Close()
	}
	return nil
}
