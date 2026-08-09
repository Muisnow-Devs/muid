package app

// ConfigEnvPrefix namespaces this gateway's env vars (GATEWAY_PUBLIC_*).
const ConfigEnvPrefix = "GATEWAY_PUBLIC"

// Config is the public gateway's envconfig contract. The public gateway is the
// untrusted-internet edge: it fronts the OIDC REST + JWKS surface and runs the
// bot/abuse-protection middleware (rate limiting, risk model, CSRF, Turnstile,
// MaxMind IP resolution) before forwarding to authn over gRPC.
type Config struct {
	Debug bool `envconfig:"DEBUG" default:"false"`
	Port  int  `envconfig:"PORT" default:"8080"`

	// AuthnGRPCAddr is the authn service address (hosts OIDCService + AuthnService).
	AuthnGRPCAddr string `envconfig:"AUTHN_GRPC_ADDR" required:"true"`

	// RedisAddr backs rate limiting, risk counters, and proof-of-work challenges.
	RedisAddr     string `envconfig:"REDIS_ADDR" required:"true"`
	RedisDatabase int    `envconfig:"REDIS_DATABASE" default:"0"`

	// TrustForwardHeader honours proxy-supplied client-IP headers. Enable ONLY
	// behind a trusted proxy (e.g. Cloudflare); otherwise clients can spoof their
	// IP. Required (explicit) in production — there is no insecure default.
	TrustForwardHeader bool `envconfig:"TRUST_FORWARD_HEADER"`
	// RealIPHeader is the single trusted-proxy header carrying the real client IP
	// (e.g. Cloudflare "CF-Connecting-IP"). Preferred over X-Forwarded-For when
	// TrustForwardHeader is set, because the proxy overwrites it (unspoofable).
	RealIPHeader string `envconfig:"REAL_IP_HEADER" default:"CF-Connecting-IP"`

	// Rate limiting (fixed window per client IP). A zero limit disables rate
	// limiting in debug; production requires a positive limit.
	RateLimit              int64 `envconfig:"RATE_LIMIT" default:"600"`
	RateLimitWindowSeconds int   `envconfig:"RATE_LIMIT_WINDOW_SECONDS" default:"60"`

	// Risk model thresholds and blocked geographies (ISO 3166-1 alpha-2).
	RiskPoWThreshold   int      `envconfig:"RISK_POW_THRESHOLD" default:"50"`
	RiskBlockThreshold int      `envconfig:"RISK_BLOCK_THRESHOLD" default:"90"`
	BlockedCountries   []string `envconfig:"BLOCKED_COUNTRIES"`

	// Proof-of-work difficulty (leading zero bits) for RequirePoW decisions.
	PoWDifficulty int `envconfig:"POW_DIFFICULTY" default:"20"`

	// CSRF signing secret; empty is permitted only in debug mode.
	CSRFSecret     string `envconfig:"CSRF_SECRET"`
	CSRFTTLSeconds int    `envconfig:"CSRF_TTL_SECONDS" default:"43200"`

	// TurnstileSecret enables real Cloudflare Turnstile verification; empty uses
	// a permissive mock (local dev / tests).
	TurnstileSecret string `envconfig:"TURNSTILE_SECRET"`

	// GeoIPPath points at a mounted MaxMind mmdb; empty uses a no-op resolver.
	GeoIPPath          string `envconfig:"GEOIP_PATH"`
	GeoIPReloadSeconds int    `envconfig:"GEOIP_RELOAD_SECONDS" default:"21600"`

	// CORSAllowedOrigins, when set, enables CORS for those origins.
	CORSAllowedOrigins []string `envconfig:"CORS_ALLOWED_ORIGINS"`

	RequestTimeoutSeconds int `envconfig:"REQUEST_TIMEOUT_SECONDS" default:"15"`

	// PersistedOpsPath points at the trusted-documents manifest (the Apollo
	// persisted-query manifest emitted by the client build). When Debug is false
	// the gateway only executes operations whose hash is in this manifest and
	// rejects ad-hoc queries; it is REQUIRED in that mode. Ignored when Debug is
	// true (arbitrary queries + introspection are allowed for development).
	PersistedOpsPath string `envconfig:"PERSISTED_OPS_PATH"`

	// Session cookie carrying the opaque session token. The default name uses the
	// __Host- prefix, which requires Secure=true, Path=/ and no Domain — the
	// refresh token is host-locked to the gateway origin.
	SessionCookieName     string `envconfig:"SESSION_COOKIE_NAME" default:"__Host-muid_session"`
	SessionCookieSecure   bool   `envconfig:"SESSION_COOKIE_SECURE" default:"true"`
	SessionCookieSameSite string `envconfig:"SESSION_COOKIE_SAMESITE" default:"Lax"`

	// Data-plane backends. The public gateway is a BFF: it fans out to authz
	// (organizations/roles/members/permissions) and profile on behalf of the
	// authenticated caller. AuthzGRPCAddr must point at authz's PUBLIC listener.
	AuthzGRPCAddr   string `envconfig:"AUTHZ_GRPC_ADDR" required:"true"`
	ProfileGRPCAddr string `envconfig:"PROFILE_GRPC_ADDR" required:"true"`

	// SessionAccessTokenIssuer must match authn's session access-token issuer; it
	// is the expected `iss` when verifying the access-token JWT locally via JWKS.
	// Required for the data plane (authz/profile). JWKSCacheTTLSeconds bounds how
	// long fetched JWKS keys are reused.
	SessionAccessTokenIssuer string `envconfig:"SESSION_ACCESS_TOKEN_ISSUER" required:"true"`
	JWKSCacheTTLSeconds      int    `envconfig:"JWKS_CACHE_TTL_SECONDS" default:"300"`

	// Access-token cookie carrying the short-lived session access-token JWT. It
	// must be readable across subdomains (the JWT is the CDN/edge fast-path
	// credential), so it uses the __Secure- prefix (NOT __Host-, which forbids a
	// Domain) plus an optional parent Domain (e.g. ".muid.io"; empty = host-only).
	AccessTokenCookieName   string `envconfig:"ACCESS_TOKEN_COOKIE_NAME" default:"__Secure-muid_at"`
	AccessTokenCookieDomain string `envconfig:"ACCESS_TOKEN_COOKIE_DOMAIN"`

	GRPCClientCertPath string `envconfig:"GRPC_CLIENT_CERT_PATH"`
	GRPCClientKeyPath  string `envconfig:"GRPC_CLIENT_KEY_PATH"`
	GRPCRootCAPath     string `envconfig:"GRPC_ROOT_CA_PATH"`
}
