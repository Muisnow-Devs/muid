package app

import (
	authzent "sanzi.io/muid/internal/authz/ent"
)

const ConfigEnvPrefix = "AUTHZ"

type Config struct {
	Debug bool `envconfig:"DEBUG" default:"false"`

	Port        int    `envconfig:"PORT"         default:"5315"`
	DatabaseURL string `envconfig:"DATABASE_URL"                required:"true"`

	RequestTimeoutSeconds int `envconfig:"REQUEST_TIMEOUT_SECONDS" default:"10"`
}

type InfraDependencies struct {
	GlobalConfig Config

	entClient *authzent.Client
}

func (d *InfraDependencies) Close() error {
	if d.entClient != nil {
		return d.entClient.Close()
	}
	return nil
}
