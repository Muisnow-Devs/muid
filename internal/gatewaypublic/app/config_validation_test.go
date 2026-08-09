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
		{name: "valid production config", env: publicProductionEnv()},
		{
			name:        "missing explicit production setting",
			env:         publicProductionEnvWithout("GATEWAY_PUBLIC_TRUST_FORWARD_HEADER"),
			wantErrPart: "GATEWAY_PUBLIC_TRUST_FORWARD_HEADER",
		},
		{
			name: "empty production CSRF secret",
			mutate: func(cfg *Config) {
				cfg.CSRFSecret = ""
			},
			env:         publicProductionEnv(),
			wantErrPart: "at least 32 bytes",
		},
		{
			name: "short production CSRF secret",
			mutate: func(cfg *Config) {
				cfg.CSRFSecret = "too-short"
			},
			env:         publicProductionEnv(),
			wantErrPart: "at least 32 bytes",
		},
		{
			name: "credentialed CORS wildcard",
			mutate: func(cfg *Config) {
				cfg.CORSAllowedOrigins = []string{"*"}
			},
			env:         publicProductionEnv(),
			wantErrPart: "wildcard",
		},
		{
			name: "credentialed CORS host wildcard",
			mutate: func(cfg *Config) {
				cfg.CORSAllowedOrigins = []string{"https://*.example.com"}
			},
			env:         publicProductionEnv(),
			wantErrPart: "wildcard",
		},
		{
			name: "production HTTP origin",
			mutate: func(cfg *Config) {
				cfg.CORSAllowedOrigins = []string{"http://app.example.com"}
			},
			env:         publicProductionEnv(),
			wantErrPart: "HTTPS",
		},
		{
			name: "origin with path",
			mutate: func(cfg *Config) {
				cfg.CORSAllowedOrigins = []string{"https://app.example.com/"}
			},
			env:         publicProductionEnv(),
			wantErrPart: "only scheme and host",
		},
		{
			name: "origin with invalid port",
			mutate: func(cfg *Config) {
				cfg.CORSAllowedOrigins = []string{"https://app.example.com:65536"}
			},
			env:         publicProductionEnv(),
			wantErrPart: "invalid port",
		},
		{
			name: "duplicate origin",
			mutate: func(cfg *Config) {
				cfg.CORSAllowedOrigins = []string{"https://app.example.com", "https://app.example.com"}
			},
			env:         publicProductionEnv(),
			wantErrPart: "duplicated",
		},
		{
			name: "invalid SameSite",
			mutate: func(cfg *Config) {
				cfg.SessionCookieSameSite = "Default"
			},
			env:         publicProductionEnv(),
			wantErrPart: "SAMESITE",
		},
		{
			name: "insecure production cookie",
			mutate: func(cfg *Config) {
				cfg.SessionCookieSecure = false
			},
			env:         publicProductionEnv(),
			wantErrPart: "secure in production",
		},
		{
			name: "host-prefixed cookie with domain",
			mutate: func(cfg *Config) {
				cfg.AccessTokenCookieName = "__Host-muid_at"
				cfg.AccessTokenCookieDomain = "example.com"
			},
			env:         publicProductionEnv(),
			wantErrPart: "must not set a domain",
		},
		{
			name: "invalid port",
			mutate: func(cfg *Config) {
				cfg.Port = 0
			},
			env:         publicProductionEnv(),
			wantErrPart: "PORT",
		},
		{
			name: "reversed risk thresholds",
			mutate: func(cfg *Config) {
				cfg.RiskPoWThreshold = cfg.RiskBlockThreshold
			},
			env:         publicProductionEnv(),
			wantErrPart: "risk thresholds",
		},
		{
			name: "production zero rate limit",
			mutate: func(cfg *Config) {
				cfg.RateLimit = 0
			},
			env:         publicProductionEnv(),
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
			name: "nonpositive timeout",
			mutate: func(cfg *Config) {
				cfg.RequestTimeoutSeconds = 0
			},
			env:         publicProductionEnv(),
			wantErrPart: "must be positive",
		},
		{
			name: "debug permits loopback HTTP and local security mocks",
			mutate: func(cfg *Config) {
				cfg.Debug = true
				cfg.CSRFSecret = ""
				cfg.TurnstileSecret = ""
				cfg.PersistedOpsPath = ""
				cfg.CORSAllowedOrigins = []string{"http://localhost:3000", "http://127.0.0.1:8080"}
				cfg.SessionCookieName = "muid_session"
				cfg.AccessTokenCookieName = "muid_at"
				cfg.SessionCookieSecure = false
			},
			env: map[string]string{},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			cfg := validPublicConfig()
			if test.mutate != nil {
				test.mutate(&cfg)
			}
			err := cfg.validate(publicMapLookup(test.env))
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

func validPublicConfig() Config {
	return Config{
		Port:                     8080,
		AuthnGRPCAddr:            "authn.example.com:443",
		RedisAddr:                "redis.example.com:6379",
		RealIPHeader:             "CF-Connecting-IP",
		RateLimit:                600,
		RateLimitWindowSeconds:   60,
		RiskPoWThreshold:         50,
		RiskBlockThreshold:       90,
		PoWDifficulty:            20,
		CSRFSecret:               "0123456789abcdef0123456789abcdef",
		CSRFTTLSeconds:           43200,
		TurnstileSecret:          "turnstile-secret",
		GeoIPReloadSeconds:       21600,
		CORSAllowedOrigins:       []string{"https://app.example.com"},
		RequestTimeoutSeconds:    15,
		PersistedOpsPath:         "config/persisted-operations.json",
		SessionCookieName:        "__Host-muid_session",
		SessionCookieSecure:      true,
		SessionCookieSameSite:    "Lax",
		AuthzGRPCAddr:            "authz.example.com:443",
		ProfileGRPCAddr:          "profile.example.com:443",
		SessionAccessTokenIssuer: "https://id.example.com",
		JWKSCacheTTLSeconds:      300,
		AccessTokenCookieName:    "__Secure-muid_at",
		AccessTokenCookieDomain:  "example.com",
	}
}

func publicProductionEnv() map[string]string {
	return map[string]string{
		"GATEWAY_PUBLIC_CSRF_SECRET":          "set",
		"GATEWAY_PUBLIC_TURNSTILE_SECRET":     "set",
		"GATEWAY_PUBLIC_CORS_ALLOWED_ORIGINS": "set",
		"GATEWAY_PUBLIC_TRUST_FORWARD_HEADER": "false",
		"GATEWAY_PUBLIC_PERSISTED_OPS_PATH":   "set",
	}
}

func publicProductionEnvWithout(name string) map[string]string {
	env := publicProductionEnv()
	delete(env, name)
	return env
}

func publicMapLookup(env map[string]string) shared.EnvLookup {
	return func(name string) (string, bool) {
		value, ok := env[name]
		return value, ok
	}
}
