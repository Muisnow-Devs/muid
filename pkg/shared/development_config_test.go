package shared

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateRequiredEnvInProduction(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		debug   bool
		env     map[string]string
		wantErr bool
	}{
		{
			name:    "debug false rejects missing env",
			debug:   false,
			env:     map[string]string{},
			wantErr: true,
		},
		{
			name:    "debug true allows missing env",
			debug:   true,
			env:     map[string]string{},
			wantErr: false,
		},
		{
			name:  "present default-looking value allowed without debug",
			debug: false,
			env: map[string]string{
				"SERVICE_PASSKEY_RP_ID":      "localhost",
				"SERVICE_PASSKEY_RP_ORIGINS": `["http://localhost"]`,
			},
			wantErr: false,
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := ValidateRequiredEnvInProduction(
				tc.debug,
				"SERVICE_DEBUG",
				mapLookup(tc.env),
				[]string{"SERVICE_PASSKEY_RP_ID", "SERVICE_PASSKEY_RP_ORIGINS"},
			)
			if tc.wantErr {
				if !errors.Is(err, ErrRequiredEnvMissing) {
					t.Fatalf("error = %v, want %v", err, ErrRequiredEnvMissing)
				}
				return
			}
			if err != nil {
				t.Fatalf("ValidateRequiredEnvInProduction() error = %v", err)
			}
		})
	}
}

func TestRequiredEnvMissingErrorDoesNotIncludeValue(t *testing.T) {
	t.Parallel()

	err := ValidateRequiredEnvInProduction(
		false,
		"SERVICE_DEBUG",
		mapLookup(map[string]string{}),
		[]string{"SERVICE_OIDC_CLIENTS_JSON"},
	)
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), "[]") {
		t.Fatalf("error %q leaked default value", err.Error())
	}
	if !strings.Contains(err.Error(), "SERVICE_OIDC_CLIENTS_JSON") ||
		!strings.Contains(err.Error(), "SERVICE_DEBUG=true") {
		t.Fatalf("error %q should name field and debug env", err.Error())
	}
}

func mapLookup(env map[string]string) EnvLookup {
	return func(name string) (string, bool) {
		value, ok := env[name]
		return value, ok
	}
}
