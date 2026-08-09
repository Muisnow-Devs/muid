package app

import (
	"strings"
	"testing"

	"github.com/google/uuid"

	"sanzi.io/muid/pkg/shared"
)

func TestConfigValidate(t *testing.T) {
	t.Parallel()

	adminID := uuid.NewString()
	tests := []struct {
		name        string
		mutate      func(*Config)
		env         map[string]string
		wantErrPart string
	}{
		{name: "valid production config", env: internalProductionEnv()},
		{
			name: "empty admin allowlist fails closed in debug",
			mutate: func(cfg *Config) {
				cfg.Debug = true
				cfg.AdminUserIDs = nil
			},
			env:         map[string]string{},
			wantErrPart: "must not be empty",
		},
		{
			name: "invalid admin UUID",
			mutate: func(cfg *Config) {
				cfg.AdminUserIDs = []string{"not-a-uuid"}
			},
			env:         internalProductionEnv(),
			wantErrPart: "invalid UUID",
		},
		{
			name: "nil admin UUID",
			mutate: func(cfg *Config) {
				cfg.AdminUserIDs = []string{uuid.Nil.String()}
			},
			env:         internalProductionEnv(),
			wantErrPart: "invalid UUID",
		},
		{
			name: "duplicate canonical admin UUID",
			mutate: func(cfg *Config) {
				cfg.AdminUserIDs = []string{adminID, strings.ToUpper(adminID)}
			},
			env:         internalProductionEnv(),
			wantErrPart: "duplicate UUID",
		},
		{
			name:        "missing explicit production allowlist",
			env:         internalProductionEnvWithout("GATEWAY_INTERNAL_ADMIN_USER_IDS"),
			wantErrPart: "GATEWAY_INTERNAL_ADMIN_USER_IDS",
		},
		{
			name: "empty required address",
			mutate: func(cfg *Config) {
				cfg.AuthzInternalGRPCAddr = " "
			},
			env:         internalProductionEnv(),
			wantErrPart: "AUTHZ_INTERNAL_GRPC_ADDR",
		},
		{
			name: "invalid port",
			mutate: func(cfg *Config) {
				cfg.Port = 65536
			},
			env:         internalProductionEnv(),
			wantErrPart: "PORT",
		},
		{
			name: "production zero rate limit",
			mutate: func(cfg *Config) {
				cfg.RateLimit = 0
			},
			env:         internalProductionEnv(),
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
			name: "reversed risk thresholds",
			mutate: func(cfg *Config) {
				cfg.RiskPoWThreshold = cfg.RiskBlockThreshold
			},
			env:         internalProductionEnv(),
			wantErrPart: "risk thresholds",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			cfg := validInternalConfig(adminID)
			if test.mutate != nil {
				test.mutate(&cfg)
			}
			err := cfg.validate(internalMapLookup(test.env))
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

func validInternalConfig(adminID string) Config {
	return Config{
		Port:                     8082,
		AuthnGRPCAddr:            "authn.example.com:443",
		AuthzInternalGRPCAddr:    "authz.example.com:443",
		RedisAddr:                "redis.example.com:6379",
		RealIPHeader:             "CF-Connecting-IP",
		SessionAccessTokenIssuer: "https://id.example.com",
		JWKSCacheTTLSeconds:      300,
		AdminUserIDs:             []string{adminID},
		RateLimit:                300,
		RateLimitWindowSeconds:   60,
		RiskPoWThreshold:         60,
		RiskBlockThreshold:       100,
		RequestTimeoutSeconds:    15,
	}
}

func internalProductionEnv() map[string]string {
	return map[string]string{
		"GATEWAY_INTERNAL_TRUST_FORWARD_HEADER": "false",
		"GATEWAY_INTERNAL_ADMIN_USER_IDS":       "set",
	}
}

func internalProductionEnvWithout(name string) map[string]string {
	env := internalProductionEnv()
	delete(env, name)
	return env
}

func internalMapLookup(env map[string]string) shared.EnvLookup {
	return func(name string) (string, bool) {
		value, ok := env[name]
		return value, ok
	}
}
