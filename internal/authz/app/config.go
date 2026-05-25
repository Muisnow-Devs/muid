package app

import (
	"errors"

	authzent "sanzi.io/muid/internal/authz/ent"
	"sanzi.io/muid/internal/signature"
)

const ConfigEnvPrefix = "AUTHZ"

type Config struct {
	Debug bool `envconfig:"DEBUG" default:"false"`

	Port        int    `envconfig:"PORT"         default:"5315"`
	DatabaseURL string `envconfig:"DATABASE_URL"                required:"true"`

	RequestTimeoutSeconds int `envconfig:"REQUEST_TIMEOUT_SECONDS" default:"10"`

	SignatureSecretName          string `envconfig:"SIGNATURE_SECRET_NAME"           required:"true"`
	SignatureKeyBits             int    `envconfig:"SIGNATURE_KEY_BITS"                              default:"2048"`
	SignaturePreviousGenerations int    `envconfig:"SIGNATURE_PREVIOUS_GENERATIONS"                  default:"1"`
	SignatureRotationPeriodHours int    `envconfig:"SIGNATURE_ROTATION_PERIOD_HOURS"                 default:"720"`
	SecretManagerGCPProjectID    string `envconfig:"SECRET_MANAGER_GCP_PROJECT_ID"                   default:""`
	SecretManagerGCPCredentials  string `envconfig:"SECRET_MANAGER_GCP_CREDENTIALS"                  default:""`
}

type InfraDependencies struct {
	GlobalConfig Config

	SignatureManager signature.SignatureManager

	entClient *authzent.Client
}

func (d *InfraDependencies) Close() error {
	var errs []error
	if d.entClient != nil {
		err := d.entClient.Close()
		if err != nil {
			errs = append(errs, err)
		}
	}
	if d.SignatureManager != nil {
		err := d.SignatureManager.Close()
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
