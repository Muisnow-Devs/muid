package config

import (
	"encoding/json"
	"strings"

	"sanzi.io/muid/pkg/utils"
)

type PasskeyConfig struct {
	RPID          string
	RPDisplayName string
	RPOrigins     []string
}

func DefaultPasskeyConfig() PasskeyConfig {
	return PasskeyConfig{
		RPID:          "localhost",
		RPDisplayName: "muid",
		RPOrigins:     []string{"http://localhost", "http://localhost:3000", "https://localhost"},
	}
}

type PasskeyOrigins []string

func (o *PasskeyOrigins) Decode(raw string) error {
	origins, err := parsePasskeyOrigins(raw)
	if err != nil {
		return err
	}
	*o = origins
	return nil
}

func ParsePasskeyConfig(
	rpID string,
	rpDisplayName string,
	origins PasskeyOrigins,
) PasskeyConfig {
	return PasskeyConfig{
		RPID:          strings.TrimSpace(rpID),
		RPDisplayName: strings.TrimSpace(rpDisplayName),
		RPOrigins:     origins.values(),
	}
}

func (o PasskeyOrigins) values() []string {
	if len(o) == 0 {
		return DefaultPasskeyConfig().RPOrigins
	}
	return []string(o)
}

func parsePasskeyOrigins(raw string) ([]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return DefaultPasskeyConfig().RPOrigins, nil
	}

	if strings.HasPrefix(raw, "[") {
		var origins []string
		err := json.Unmarshal([]byte(raw), &origins)
		if err != nil {
			return nil, err
		}
		return utils.TrimNonEmpty(origins), nil
	}

	return utils.TrimNonEmpty(strings.Split(raw, ",")), nil
}
