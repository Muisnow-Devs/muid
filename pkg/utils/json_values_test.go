package utils

import (
	"encoding/json"
	"testing"
)

func TestJSONStringField(t *testing.T) {
	t.Parallel()

	raw := rawJSONFields(t, `{"name": " Ada Lovelace ", "age": 36}`)
	got := JSONStringField(raw, " name ")
	if got != "Ada Lovelace" {
		t.Fatalf("JSONStringField() = %q, want Ada Lovelace", got)
	}
}

func TestJSONStringFieldNonString(t *testing.T) {
	t.Parallel()

	raw := rawJSONFields(t, `{"name": 123}`)
	got := JSONStringField(raw, "name")
	if got != "" {
		t.Fatalf("JSONStringField() = %q, want empty", got)
	}
}

func TestJSONBoolField(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{name: "bool true", input: `{"verified": true}`, want: true},
		{name: "string true", input: `{"verified": " true "}`, want: true},
		{name: "string false", input: `{"verified": "false"}`, want: false},
		{name: "invalid string", input: `{"verified": "yes"}`, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			raw := rawJSONFields(t, tt.input)
			got := JSONBoolField(raw, "verified")
			if got != tt.want {
				t.Fatalf("JSONBoolField() = %v, want %v", got, tt.want)
			}
		})
	}
}

func rawJSONFields(t *testing.T, input string) map[string]json.RawMessage {
	t.Helper()

	var raw map[string]json.RawMessage
	err := json.Unmarshal([]byte(input), &raw)
	if err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	return raw
}
