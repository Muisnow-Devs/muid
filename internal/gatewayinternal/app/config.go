package app

// ConfigEnvPrefix namespaces this gateway's env vars (GATEWAY_INTERNAL_*).
const ConfigEnvPrefix = "GATEWAY_INTERNAL"

// Config is the internal gateway's envconfig contract. The internal gateway is
// the ops/admin edge: it must never be internet-exposed. It authenticates admin
// callers by JWT, applies rate limiting and a lightweight risk check, and
// proxies onto the internal gRPC admin surfaces.
type Config struct {
	Debug bool `envconfig:"DEBUG" default:"false"`
	Port  int  `envconfig:"PORT" default:"8082"`

	// AuthnGRPCAddr hosts OIDCClientAdminService and SigningKeyService.GetPublicKeys (JWKS).
	AuthnGRPCAddr string `envconfig:"AUTHN_GRPC_ADDR" required:"true"`
	// AuthzInternalGRPCAddr hosts AuthzAdminService (internal listener).
	AuthzInternalGRPCAddr string `envconfig:"AUTHZ_INTERNAL_GRPC_ADDR" required:"true"`

	// RedisAddr backs rate limiting and risk counters.
	RedisAddr     string `envconfig:"REDIS_ADDR" required:"true"`
	RedisDatabase int    `envconfig:"REDIS_DATABASE" default:"0"`

	// TrustForwardHeader honours proxy-supplied client-IP headers (internal proxy
	// only). Required (explicit) in production — no insecure default.
	TrustForwardHeader bool `envconfig:"TRUST_FORWARD_HEADER"`
	// RealIPHeader is the trusted-proxy header carrying the real client IP,
	// preferred over X-Forwarded-For when TrustForwardHeader is set.
	RealIPHeader string `envconfig:"REAL_IP_HEADER" default:"CF-Connecting-IP"`

	// SessionAccessTokenIssuer is the expected admin JWT issuer.
	SessionAccessTokenIssuer string `envconfig:"SESSION_ACCESS_TOKEN_ISSUER" required:"true"`
	JWKSCacheTTLSeconds      int    `envconfig:"JWKS_CACHE_TTL_SECONDS" default:"300"`

	// Ingress mTLS accepts only the admin-ingress SPIFFE workload. The full group
	// is mandatory in every mode.
	MTLSClientCAPath string `envconfig:"MTLS_CLIENT_CA_PATH"`
	TLSCertPath      string `envconfig:"TLS_CERT_PATH"`
	TLSKeyPath       string `envconfig:"TLS_KEY_PATH"`

	// Backend mTLS presents the gateway-internal workload certificate and
	// verifies Authn/Authz server names against the configured roots.
	GRPCClientCertPath string `envconfig:"GRPC_CLIENT_CERT_PATH"`
	GRPCClientKeyPath  string `envconfig:"GRPC_CLIENT_KEY_PATH"`
	GRPCRootCAPath     string `envconfig:"GRPC_ROOT_CA_PATH"`

	// Rate limiting (fixed window per admin user). A zero limit disables rate
	// limiting in debug; production requires a positive limit.
	RateLimit              int64 `envconfig:"RATE_LIMIT" default:"300"`
	RateLimitWindowSeconds int   `envconfig:"RATE_LIMIT_WINDOW_SECONDS" default:"60"`

	// Risk thresholds (no geo/CAPTCHA at the internal edge).
	RiskPoWThreshold   int `envconfig:"RISK_POW_THRESHOLD" default:"60"`
	RiskBlockThreshold int `envconfig:"RISK_BLOCK_THRESHOLD" default:"100"`

	RequestTimeoutSeconds int `envconfig:"REQUEST_TIMEOUT_SECONDS" default:"15"`
}
