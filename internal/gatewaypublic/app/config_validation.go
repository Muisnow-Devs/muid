package app

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"sanzi.io/muid/pkg/shared"
)

const (
	minimumCSRFSecretBytes = 32
	maximumPoWDifficulty   = 256
)

// Validate checks the public gateway configuration. Debug mode relaxes only
// production-only security controls; semantic safety checks always apply.
func (cfg Config) Validate() error {
	return cfg.validate(os.LookupEnv)
}

func (cfg Config) validate(lookup shared.EnvLookup) error {
	err := shared.ValidateRequiredEnvInProduction(cfg.Debug, "GATEWAY_PUBLIC_DEBUG", lookup, []string{
		"GATEWAY_PUBLIC_CSRF_SECRET",
		"GATEWAY_PUBLIC_TURNSTILE_SECRET",
		"GATEWAY_PUBLIC_CORS_ALLOWED_ORIGINS",
		"GATEWAY_PUBLIC_TRUST_FORWARD_HEADER",
		"GATEWAY_PUBLIC_PERSISTED_OPS_PATH",
	})
	if err != nil {
		return err
	}
	return cfg.validateValues()
}

func (cfg Config) validateValues() error {
	for _, field := range []struct {
		name  string
		value string
	}{
		{name: "AUTHN_GRPC_ADDR", value: cfg.AuthnGRPCAddr},
		{name: "REDIS_ADDR", value: cfg.RedisAddr},
		{name: "AUTHZ_GRPC_ADDR", value: cfg.AuthzGRPCAddr},
		{name: "PROFILE_GRPC_ADDR", value: cfg.ProfileGRPCAddr},
		{name: "SESSION_ACCESS_TOKEN_ISSUER", value: cfg.SessionAccessTokenIssuer},
	} {
		if strings.TrimSpace(field.value) == "" {
			return fmt.Errorf("gateway public %s must not be empty", field.name)
		}
	}
	if cfg.Port < 1 || cfg.Port > 65535 {
		return fmt.Errorf("gateway public PORT must be between 1 and 65535")
	}
	if cfg.RedisDatabase < 0 {
		return fmt.Errorf("gateway public REDIS_DATABASE must not be negative")
	}
	if cfg.RateLimit < 0 {
		return fmt.Errorf("gateway public RATE_LIMIT must not be negative")
	}
	if !cfg.Debug && cfg.RateLimit == 0 {
		return fmt.Errorf("gateway public RATE_LIMIT must be positive in production")
	}
	if cfg.RateLimitWindowSeconds <= 0 {
		return fmt.Errorf("gateway public RATE_LIMIT_WINDOW_SECONDS must be positive")
	}
	if cfg.RiskPoWThreshold <= 0 || cfg.RiskPoWThreshold >= cfg.RiskBlockThreshold || cfg.RiskBlockThreshold > 100 {
		return fmt.Errorf("gateway public risk thresholds must satisfy 0 < PoW < block <= 100")
	}
	if cfg.PoWDifficulty <= 0 || cfg.PoWDifficulty > maximumPoWDifficulty {
		return fmt.Errorf("gateway public POW_DIFFICULTY must be between 1 and %d", maximumPoWDifficulty)
	}
	if cfg.CSRFTTLSeconds <= 0 || cfg.GeoIPReloadSeconds <= 0 || cfg.RequestTimeoutSeconds <= 0 || cfg.JWKSCacheTTLSeconds <= 0 {
		return fmt.Errorf("gateway public TTL, reload, request timeout, and JWKS cache values must be positive")
	}
	if cfg.TrustForwardHeader && strings.TrimSpace(cfg.RealIPHeader) == "" {
		return fmt.Errorf("gateway public REAL_IP_HEADER must not be empty when forwarding headers are trusted")
	}
	if !cfg.Debug {
		if len([]byte(cfg.CSRFSecret)) < minimumCSRFSecretBytes || strings.TrimSpace(cfg.CSRFSecret) == "" {
			return fmt.Errorf("gateway public CSRF_SECRET must contain at least %d bytes in production", minimumCSRFSecretBytes)
		}
		if strings.TrimSpace(cfg.TurnstileSecret) == "" {
			return fmt.Errorf("gateway public TURNSTILE_SECRET must not be empty in production")
		}
		if strings.TrimSpace(cfg.PersistedOpsPath) == "" {
			return fmt.Errorf("gateway public PERSISTED_OPS_PATH must not be empty in production")
		}
	}
	err := validateAllowedOrigins(cfg.CORSAllowedOrigins, !cfg.Debug)
	if err != nil {
		return err
	}
	return cfg.validateCookies()
}

func validateAllowedOrigins(origins []string, production bool) error {
	if production && len(origins) == 0 {
		return fmt.Errorf("gateway public CORS_ALLOWED_ORIGINS must not be empty in production")
	}
	seen := make(map[string]struct{}, len(origins))
	for _, origin := range origins {
		if strings.Contains(origin, "*") {
			return fmt.Errorf("gateway public CORS_ALLOWED_ORIGINS must not contain a wildcard with credentialed CORS")
		}
		if origin == "" || origin != strings.TrimSpace(origin) {
			return fmt.Errorf("gateway public CORS origin %q is not normalized", origin)
		}
		parsed, err := url.Parse(origin)
		if err != nil {
			return fmt.Errorf("gateway public CORS origin %q is invalid: %w", origin, err)
		}
		if parsed.User != nil || parsed.Hostname() == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Opaque != "" {
			return fmt.Errorf("gateway public CORS origin %q must contain only scheme and host", origin)
		}
		if parsed.Scheme != "https" && !(parsed.Scheme == "http" && !production && isLoopbackHost(parsed.Hostname())) {
			return fmt.Errorf("gateway public CORS origin %q must use HTTPS", origin)
		}
		if origin != parsed.Scheme+"://"+parsed.Host {
			return fmt.Errorf("gateway public CORS origin %q is not normalized", origin)
		}
		if port := parsed.Port(); port != "" {
			portNumber, err := strconv.Atoi(port)
			if err != nil || portNumber < 1 || portNumber > 65535 {
				return fmt.Errorf("gateway public CORS origin %q contains an invalid port", origin)
			}
		}
		if _, ok := seen[origin]; ok {
			return fmt.Errorf("gateway public CORS origin %q is duplicated", origin)
		}
		seen[origin] = struct{}{}
	}
	return nil
}

func isLoopbackHost(host string) bool {
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (cfg Config) validateCookies() error {
	if cfg.SessionCookieName == "" || cfg.AccessTokenCookieName == "" {
		return fmt.Errorf("gateway public cookie names must not be empty")
	}
	if cfg.SessionCookieName == cfg.AccessTokenCookieName {
		return fmt.Errorf("gateway public session and access-token cookie names must differ")
	}
	sameSite := strings.ToLower(strings.TrimSpace(cfg.SessionCookieSameSite))
	if sameSite != "lax" && sameSite != "strict" && sameSite != "none" {
		return fmt.Errorf("gateway public SESSION_COOKIE_SAMESITE must be Lax, Strict, or None")
	}
	if !cfg.Debug && !cfg.SessionCookieSecure {
		return fmt.Errorf("gateway public session cookies must be secure in production")
	}
	if sameSite == "none" && !cfg.SessionCookieSecure {
		return fmt.Errorf("gateway public SameSite=None cookies must be secure")
	}
	if (strings.HasPrefix(cfg.SessionCookieName, "__Host-") || strings.HasPrefix(cfg.SessionCookieName, "__Secure-")) && !cfg.SessionCookieSecure {
		return fmt.Errorf("gateway public prefixed session cookie must be secure")
	}
	if (strings.HasPrefix(cfg.AccessTokenCookieName, "__Host-") || strings.HasPrefix(cfg.AccessTokenCookieName, "__Secure-")) && !cfg.SessionCookieSecure {
		return fmt.Errorf("gateway public prefixed access-token cookie must be secure")
	}
	if strings.HasPrefix(cfg.AccessTokenCookieName, "__Host-") && strings.TrimSpace(cfg.AccessTokenCookieDomain) != "" {
		return fmt.Errorf("gateway public __Host- access-token cookie must not set a domain")
	}
	sessionCookie := &http.Cookie{Name: cfg.SessionCookieName, Value: "value", Path: "/", Secure: cfg.SessionCookieSecure}
	err := sessionCookie.Valid()
	if err != nil {
		return fmt.Errorf("gateway public session cookie is invalid: %w", err)
	}
	if cfg.AccessTokenCookieDomain != strings.TrimSpace(cfg.AccessTokenCookieDomain) {
		return fmt.Errorf("gateway public access-token cookie domain is not normalized")
	}
	accessCookie := &http.Cookie{
		Name:   cfg.AccessTokenCookieName,
		Value:  "value",
		Path:   "/",
		Domain: cfg.AccessTokenCookieDomain,
		Secure: cfg.SessionCookieSecure,
	}
	err = accessCookie.Valid()
	if err != nil {
		return fmt.Errorf("gateway public access-token cookie is invalid: %w", err)
	}
	return nil
}
