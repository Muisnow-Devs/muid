package config

import (
	"encoding/json"
	"strings"

	"sanzi.io/muid/internal/authn/identity"
	"sanzi.io/muid/pkg/utils"
)

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
) identity.PasskeyConfig {
	return identity.PasskeyConfig{
		RPID:          strings.TrimSpace(rpID),
		RPDisplayName: strings.TrimSpace(rpDisplayName),
		RPOrigins:     origins.values(),
	}
}

func (o PasskeyOrigins) values() []string {
	if len(o) == 0 {
		return identity.DefaultPasskeyConfig().RPOrigins
	}
	return []string(o)
}

func parsePasskeyOrigins(raw string) ([]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return identity.DefaultPasskeyConfig().RPOrigins, nil
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
