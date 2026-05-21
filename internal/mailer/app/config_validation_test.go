package app

import (
	"errors"
	"testing"

	"sanzi.io/muid/pkg/shared"
)

func TestConfigValidateDefaultValues(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		cfg     Config
		env     map[string]string
		wantErr bool
	}{
		{
			name: "debug false rejects missing critical env",
			cfg: Config{
				NATSURL:  "nats://localhost:4222",
				SMTPHost: "smtp.example.com",
				SMTPFrom: "noreply@example.com",
			},
			env:     mailerEnvWithout("MAILER_SMTP_FROM"),
			wantErr: true,
		},
		{
			name: "debug true allows missing critical env",
			cfg: Config{
				Debug:    true,
				NATSURL:  "nats://localhost:4222",
				SMTPHost: "127.0.0.1",
			},
			env:     map[string]string{},
			wantErr: false,
		},
		{
			name: "production env present allowed without debug",
			cfg: Config{
				NATSURL:  "nats://nats.example.com:4222",
				SMTPHost: "smtp.example.com",
				SMTPFrom: "noreply@example.com",
			},
			env:     mailerEnv(),
			wantErr: false,
		},
		{
			name: "default-looking localhost value allowed when env is explicit",
			cfg: Config{
				NATSURL:  "nats://localhost:4222",
				SMTPHost: "localhost",
				SMTPFrom: "noreply@example.com",
			},
			env: mailerEnvWith(map[string]string{
				"MAILER_NATS_URL":  "nats://localhost:4222",
				"MAILER_SMTP_HOST": "localhost",
			}),
			wantErr: false,
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := tc.cfg.validate(mapLookup(tc.env))
			if tc.wantErr {
				if !errors.Is(err, shared.ErrRequiredEnvMissing) {
					t.Fatalf("error = %v, want %v", err, shared.ErrRequiredEnvMissing)
				}
				return
			}
			if err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
		})
	}
}

func mailerEnv() map[string]string {
	return map[string]string{
		"MAILER_NATS_URL":  "nats://nats.example.com:4222",
		"MAILER_SMTP_HOST": "smtp.example.com",
		"MAILER_SMTP_FROM": "noreply@example.com",
	}
}

func mailerEnvWithout(envName string) map[string]string {
	env := mailerEnv()
	delete(env, envName)
	return env
}

func mailerEnvWith(overrides map[string]string) map[string]string {
	env := mailerEnv()
	for name, value := range overrides {
		env[name] = value
	}
	return env
}

func mapLookup(env map[string]string) shared.EnvLookup {
	return func(name string) (string, bool) {
		value, ok := env[name]
		return value, ok
	}
}
