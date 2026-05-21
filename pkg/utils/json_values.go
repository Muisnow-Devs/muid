package utils

import (
	"encoding/json"
	"strings"
)

func JSONStringField(raw map[string]json.RawMessage, field string) string {
	value, ok := raw[strings.TrimSpace(field)]
	if !ok {
		return ""
	}

	var out string
	err := json.Unmarshal(value, &out)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

func JSONBoolField(raw map[string]json.RawMessage, field string) bool {
	value, ok := raw[strings.TrimSpace(field)]
	if !ok {
		return false
	}

	var out bool
	err := json.Unmarshal(value, &out)
	if err == nil {
		return out
	}

	var asString string
	err = json.Unmarshal(value, &asString)
	return err == nil && strings.EqualFold(strings.TrimSpace(asString), "true")
}
