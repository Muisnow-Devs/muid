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
				Port:                      5324,
				DatabaseURL:               "postgres://user:pass@db.example.com:5432/profile",
				NATSURL:                   "nats://nats.example.com:4222",
				RequestTimeoutSeconds:     10,
				AuthzRoleCacheTTLSeconds:  300,
				AuthzPolicyRefreshSeconds: 300,
				R2AccountID:               "account",
				GRPCTLSCertPath:           "server.pem",
				GRPCTLSKeyPath:            "server-key.pem",
				GRPCMTLSClientCAPath:      "clients.pem",
				GRPCClientCertPath:        "client.pem",
				GRPCClientKeyPath:         "client-key.pem",
				GRPCRootCAPath:            "servers.pem",
			},
			env:     profileEnvWithout("PROFILE_PUBLIC_ASSETS_URL"),
			wantErr: true,
		},
		{
			name: "debug true allows missing critical env with mutual TLS",
			cfg: Config{
				Debug:                     true,
				Port:                      5324,
				DatabaseURL:               "postgres://user:pass@db.example.com:5432/profile",
				NATSURL:                   "nats://nats.example.com:4222",
				RequestTimeoutSeconds:     10,
				AuthzRoleCacheTTLSeconds:  300,
				AuthzPolicyRefreshSeconds: 300,
				R2AccountID:               "account",
				GRPCTLSCertPath:           "server.pem",
				GRPCTLSKeyPath:            "server-key.pem",
				GRPCMTLSClientCAPath:      "clients.pem",
				GRPCClientCertPath:        "client.pem",
				GRPCClientKeyPath:         "client-key.pem",
				GRPCRootCAPath:            "servers.pem",
			},
			env:     map[string]string{},
			wantErr: false,
		},
		{
			name: "production env present allowed without debug",
			cfg: Config{
				Port:                      5324,
				DatabaseURL:               "postgres://user:pass@db.example.com:5432/profile",
				NATSURL:                   "nats://nats.example.com:4222",
				RequestTimeoutSeconds:     10,
				AuthzRoleCacheTTLSeconds:  300,
				AuthzPolicyRefreshSeconds: 300,
				PublicAssetURL:            "https://assets.example.com",
				R2AccountID:               "account",
				GRPCTLSCertPath:           "server.pem",
				GRPCTLSKeyPath:            "server-key.pem",
				GRPCMTLSClientCAPath:      "clients.pem",
				GRPCClientCertPath:        "client.pem",
				GRPCClientKeyPath:         "client-key.pem",
				GRPCRootCAPath:            "servers.pem",
			},
			env:     profileEnv(),
			wantErr: false,
		},
		{
			name: "default-looking localhost value allowed when env is explicit",
			cfg: Config{
				Port:                      5324,
				DatabaseURL:               "postgres://user:pass@db.example.com:5432/profile",
				NATSURL:                   "nats://nats.example.com:4222",
				RequestTimeoutSeconds:     10,
				AuthzRoleCacheTTLSeconds:  300,
				AuthzPolicyRefreshSeconds: 300,
				PublicAssetURL:            "http://localhost:8080/assets",
				R2AccountID:               "account",
				GRPCTLSCertPath:           "server.pem",
				GRPCTLSKeyPath:            "server-key.pem",
				GRPCMTLSClientCAPath:      "clients.pem",
				GRPCClientCertPath:        "client.pem",
				GRPCClientKeyPath:         "client-key.pem",
				GRPCRootCAPath:            "servers.pem",
			},
			env: profileEnvWith(map[string]string{
				"PROFILE_PUBLIC_ASSETS_URL": "http://localhost:8080/assets",
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

func TestConfigValidateTLSGroups(t *testing.T) {
	t.Parallel()

	base := Config{
		Debug:                     true,
		Port:                      5324,
		DatabaseURL:               "postgres://profile",
		NATSURL:                   "nats://localhost:4222",
		RequestTimeoutSeconds:     10,
		AuthzRoleCacheTTLSeconds:  300,
		AuthzPolicyRefreshSeconds: 300,
	}
	partial := base
	partial.GRPCTLSCertPath = "server.pem"
	if err := partial.validate(mapLookup(nil)); err == nil {
		t.Fatal("partial inbound TLS group was accepted")
	}

	production := base
	production.Debug = false
	if err := production.validate(mapLookup(profileEnv())); err == nil {
		t.Fatal("production without TLS groups was accepted")
	}
}

func profileEnv() map[string]string {
	return map[string]string{
		"PROFILE_DATABASE_URL":      "postgres://user:pass@db.example.com:5432/profile",
		"PROFILE_NATS_URL":          "nats://nats.example.com:4222",
		"PROFILE_PUBLIC_ASSETS_URL": "https://assets.example.com",
	}
}

func profileEnvWithout(envName string) map[string]string {
	env := profileEnv()
	delete(env, envName)
	return env
}

func profileEnvWith(overrides map[string]string) map[string]string {
	env := profileEnv()
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
