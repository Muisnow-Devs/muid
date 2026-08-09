package app

import (
	"errors"
	"testing"

	authnconfig "sanzi.io/muid/internal/authn/config"
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
			name:    "debug false rejects missing critical env",
			cfg:     validProductionConfig(),
			env:     productionEnvWithout("AUTHN_PASSKEY_RP_ID"),
			wantErr: true,
		},
		{
			name: "debug true allows missing critical env",
			cfg: func() Config {
				cfg := validProductionConfig()
				cfg.Debug = true
				return cfg
			}(),
			env:     map[string]string{},
			wantErr: false,
		},
		{
			name:    "production env present allowed without debug",
			cfg:     validProductionConfig(),
			env:     productionEnv(),
			wantErr: false,
		},
		{
			name: "default-looking localhost value allowed when env is explicit",
			cfg: func() Config {
				cfg := validProductionConfig()
				cfg.DatabaseURL = "postgres://user:pass@localhost:5432/authn"
				cfg.RedisAddr = "redis://localhost:6379/0"
				cfg.NATSURL = "nats://localhost:4222"
				cfg.ProfileGRPCAddr = "localhost:5324"
				cfg.PasskeyRPID = "localhost"
				cfg.PasskeyRPOrigins = authnconfig.PasskeyOrigins{"http://localhost", "http://localhost:3000"}
				return cfg
			}(),
			env: productionEnvWith(map[string]string{
				"AUTHN_DATABASE_URL":       "postgres://user:pass@localhost:5432/authn",
				"AUTHN_REDIS_ADDR":         "redis://localhost:6379/0",
				"AUTHN_NATS_URL":           "nats://localhost:4222",
				"AUTHN_PROFILE_GRPC_ADDR":  "localhost:5324",
				"AUTHN_PASSKEY_RP_ID":      "localhost",
				"AUTHN_PASSKEY_RP_ORIGINS": `["http://localhost","http://localhost:3000"]`,
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

func TestLoadConfigDecodesStructuredAuthnConfig(t *testing.T) {
	t.Setenv("AUTHN_DATABASE_URL", "postgres://user:pass@db.example.com:5432/authn")
	t.Setenv("AUTHN_REDIS_ADDR", "redis.example.com:6379")
	t.Setenv("AUTHN_NATS_URL", "nats://nats.example.com:4222")
	t.Setenv("AUTHN_OTP_SECRET_KEY", "00112233445566778899aabbccddeeff")
	t.Setenv("AUTHN_PROFILE_GRPC_ADDR", "profile.example.com:443")
	t.Setenv("AUTHN_PASSKEY_RP_ID", "app.example.com")
	t.Setenv("AUTHN_PASSKEY_RP_ORIGINS", `["https://app.example.com","https://admin.example.com"]`)
	t.Setenv("AUTHN_OIDC_CLIENTS_JSON", `[{
		"provider":"local",
		"endpoint":"http://127.0.0.1:5556",
		"client_id":"client",
		"client_secret":"secret",
		"redirect_url":"https://app.example.com/callback"
	}]`)

	cfg, err := shared.LoadConfig[Config](ConfigEnvPrefix)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	if len(cfg.PasskeyRPOrigins) != 2 || cfg.PasskeyRPOrigins[1] != "https://admin.example.com" {
		t.Fatalf("PasskeyRPOrigins = %+v, want decoded origins", cfg.PasskeyRPOrigins)
	}
	if len(cfg.OIDCClients) != 1 || cfg.OIDCClients[0].Name != "local" {
		t.Fatalf("OIDCClients = %+v, want decoded client", cfg.OIDCClients)
	}
}

func TestConfigValidateTLSGroups(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*Config)
		debug  bool
	}{
		{
			name: "partial inbound in debug",
			mutate: func(cfg *Config) {
				cfg.GRPCTLSKeyPath = ""
			},
			debug: true,
		},
		{
			name: "missing inbound in production",
			mutate: func(cfg *Config) {
				cfg.GRPCTLSCertPath = ""
				cfg.GRPCTLSKeyPath = ""
				cfg.GRPCMTLSClientCAPath = ""
			},
		},
		{
			name: "missing inbound in debug",
			mutate: func(cfg *Config) {
				cfg.GRPCTLSCertPath = ""
				cfg.GRPCTLSKeyPath = ""
				cfg.GRPCMTLSClientCAPath = ""
			},
			debug: true,
		},
		{
			name: "partial outbound in debug",
			mutate: func(cfg *Config) {
				cfg.GRPCRootCAPath = ""
			},
			debug: true,
		},
		{
			name: "missing outbound in production",
			mutate: func(cfg *Config) {
				cfg.GRPCClientCertPath = ""
				cfg.GRPCClientKeyPath = ""
				cfg.GRPCRootCAPath = ""
			},
		},
		{
			name: "missing outbound in debug",
			mutate: func(cfg *Config) {
				cfg.GRPCClientCertPath = ""
				cfg.GRPCClientKeyPath = ""
				cfg.GRPCRootCAPath = ""
			},
			debug: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			cfg := validProductionConfig()
			cfg.Debug = test.debug
			test.mutate(&cfg)
			lookup := mapLookup(productionEnv())
			if test.debug {
				lookup = mapLookup(nil)
			}
			if err := cfg.validate(lookup); err == nil {
				t.Fatal("invalid TLS group was accepted")
			}
		})
	}
}

func validProductionConfig() Config {
	return Config{
		DatabaseURL:           "postgres://user:pass@db.example.com:5432/authn",
		RedisAddr:             "redis://redis.example.com:6379/0",
		NATSURL:               "nats://nats.example.com:4222",
		PasskeyRPID:           "app.example.com",
		PasskeyRPOrigins:      authnconfig.PasskeyOrigins{"https://app.example.com"},
		ProfileGRPCAddr:       "profile.example.com:443",
		OTPSecretKey:          "00112233445566778899aabbccddeeff",
		ProfileGRPCMaxRetries: 2,
		GRPCTLSCertPath:       "server.pem",
		GRPCTLSKeyPath:        "server-key.pem",
		GRPCMTLSClientCAPath:  "clients.pem",
		GRPCClientCertPath:    "client.pem",
		GRPCClientKeyPath:     "client-key.pem",
		GRPCRootCAPath:        "servers.pem",
	}
}

func productionEnv() map[string]string {
	return map[string]string{
		"AUTHN_DATABASE_URL":       "postgres://user:pass@db.example.com:5432/authn",
		"AUTHN_REDIS_ADDR":         "redis://redis.example.com:6379/0",
		"AUTHN_NATS_URL":           "nats://nats.example.com:4222",
		"AUTHN_PROFILE_GRPC_ADDR":  "profile.example.com:443",
		"AUTHN_PASSKEY_RP_ID":      "app.example.com",
		"AUTHN_PASSKEY_RP_ORIGINS": `["https://app.example.com"]`,
	}
}

func productionEnvWithout(envName string) map[string]string {
	env := productionEnv()
	delete(env, envName)
	return env
}

func productionEnvWith(overrides map[string]string) map[string]string {
	env := productionEnv()
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
