package shared

import (
	"github.com/kelseyhightower/envconfig"
)

func LoadConfig[T any](prefix string) (T, error) {
	var config T
	if err := envconfig.Process(prefix, &config); err != nil {
		return config, err
	}

	return config, nil
}
