package app

import (
	"strings"
	"testing"

	"sanzi.io/muid/pkg/shared"
)

func TestConfigValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		mutate      func(*Config)
		env         map[string]string
		wantErrPart string
	}{
		{name: "valid production config", env: servicesProductionEnv()},
		{
			name:        "missing explicit production TLS key",
			env:         servicesProductionEnvWithout("GATEWAY_SERVICES_TLS_KEY_PATH"),
			wantErrPart: "GATEWAY_SERVICES_TLS_KEY_PATH",
		},
		{
			name: "empty production TLS key",
			mutate: func(cfg *Config) {
				cfg.TLSKeyPath = ""
			},
			env:         servicesProductionEnv(),
			wantErrPart: "ingress mTLS",
		},
		{
			name: "partial mTLS config in debug",
			mutate: func(cfg *Config) {
				cfg.Debug = true
				cfg.MTLSClientCAPath = ""
			},
			env:         map[string]string{},
			wantErrPart: "ingress mTLS",
		},
		{
			name: "debug rejects mTLS disabled",
			mutate: func(cfg *Config) {
				cfg.Debug = true
				cfg.MTLSClientCAPath = ""
				cfg.TLSCertPath = ""
				cfg.TLSKeyPath = ""
			},
			env:         map[string]string{},
			wantErrPart: "ingress mTLS",
		},
		{
			name: "partial outbound TLS",
			mutate: func(cfg *Config) {
				cfg.GRPCRootCAPath = ""
			},
			env:         servicesProductionEnv(),
			wantErrPart: "outbound gRPC TLS",
		},
		{
			name: "debug rejects outbound TLS disabled",
			mutate: func(cfg *Config) {
				cfg.Debug = true
				cfg.GRPCClientCertPath = ""
				cfg.GRPCClientKeyPath = ""
				cfg.GRPCRootCAPath = ""
			},
			env:         map[string]string{},
			wantErrPart: "outbound gRPC TLS",
		},
		{
			name: "empty backend address",
			mutate: func(cfg *Config) {
				cfg.ProfileGRPCAddr = " "
			},
			env:         servicesProductionEnv(),
			wantErrPart: "PROFILE_GRPC_ADDR",
		},
		{
			name: "invalid port",
			mutate: func(cfg *Config) {
				cfg.Port = -1
			},
			env:         servicesProductionEnv(),
			wantErrPart: "PORT",
		},
		{
			name: "negative Redis database",
			mutate: func(cfg *Config) {
				cfg.RedisDatabase = -1
			},
			env:         servicesProductionEnv(),
			wantErrPart: "REDIS_DATABASE",
		},
		{
			name: "production zero rate limit",
			mutate: func(cfg *Config) {
				cfg.RateLimit = 0
			},
			env:         servicesProductionEnv(),
			wantErrPart: "positive in production",
		},
		{
			name: "debug zero rate limit disables limiting",
			mutate: func(cfg *Config) {
				cfg.Debug = true
				cfg.RateLimit = 0
			},
			env: map[string]string{},
		},
		{
			name: "debug negative rate limit is invalid",
			mutate: func(cfg *Config) {
				cfg.Debug = true
				cfg.RateLimit = -1
			},
			env:         map[string]string{},
			wantErrPart: "must not be negative",
		},
		{
			name: "nonpositive request timeout",
			mutate: func(cfg *Config) {
				cfg.RequestTimeoutSeconds = 0
			},
			env:         servicesProductionEnv(),
			wantErrPart: "must be positive",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			cfg := validServicesConfig()
			if test.mutate != nil {
				test.mutate(&cfg)
			}
			err := cfg.validate(servicesMapLookup(test.env))
			if test.wantErrPart == "" {
				if err != nil {
					t.Fatalf("Config.validate() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErrPart) {
				t.Fatalf("Config.validate() error = %v, want error containing %q", err, test.wantErrPart)
			}
		})
	}
}

func validServicesConfig() Config {
	return Config{
		Port:                     8081,
		AuthnGRPCAddr:            "authn.example.com:443",
		ProfileGRPCAddr:          "profile.example.com:443",
		RedisAddr:                "redis.example.com:6379",
		SessionAccessTokenIssuer: "https://id.example.com",
		JWKSCacheTTLSeconds:      300,
		RateLimit:                1200,
		RateLimitWindowSeconds:   60,
		MTLSClientCAPath:         "certs/client-ca.pem",
		TLSCertPath:              "certs/server.pem",
		TLSKeyPath:               "certs/server-key.pem",
		GRPCClientCertPath:       "certs/client.pem",
		GRPCClientKeyPath:        "certs/client-key.pem",
		GRPCRootCAPath:           "certs/server-ca.pem",
		RequestTimeoutSeconds:    15,
	}
}

func servicesProductionEnv() map[string]string {
	return map[string]string{
		"GATEWAY_SERVICES_MTLS_CLIENT_CA_PATH":  "set",
		"GATEWAY_SERVICES_TLS_CERT_PATH":        "set",
		"GATEWAY_SERVICES_TLS_KEY_PATH":         "set",
		"GATEWAY_SERVICES_TRUST_FORWARD_HEADER": "false",
	}
}

func servicesProductionEnvWithout(name string) map[string]string {
	env := servicesProductionEnv()
	delete(env, name)
	return env
}

func servicesMapLookup(env map[string]string) shared.EnvLookup {
	return func(name string) (string, bool) {
		value, ok := env[name]
		return value, ok
	}
}
