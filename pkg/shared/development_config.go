package shared

import (
	"errors"
	"fmt"
	"os"
)

var ErrRequiredEnvMissing = errors.New("required production environment variable missing")

type EnvLookup func(string) (string, bool)

type RequiredEnvMissingError struct {
	EnvName  string
	DebugEnv string
}

func (e RequiredEnvMissingError) Error() string {
	return fmt.Sprintf(
		"environment variable %s is required for production; set %s or set %s=true for development",
		e.EnvName,
		e.EnvName,
		e.DebugEnv,
	)
}

func (e RequiredEnvMissingError) Unwrap() error {
	return ErrRequiredEnvMissing
}

// ValidateRequiredEnvInProduction ensures production deployments explicitly set
// critical env vars instead of silently relying on envconfig defaults.
func ValidateRequiredEnvInProduction(
	debug bool,
	debugEnv string,
	lookup EnvLookup,
	envNames []string,
) error {
	if debug {
		return nil
	}
	if lookup == nil {
		lookup = os.LookupEnv
	}
	for _, envName := range envNames {
		if _, ok := lookup(envName); ok {
			continue
		}
		return RequiredEnvMissingError{
			EnvName:  envName,
			DebugEnv: debugEnv,
		}
	}
	return nil
}
