package app

// ConfigEnvPrefix namespaces this gateway's env vars (GATEWAY_SERVICES_*).
const ConfigEnvPrefix = "GATEWAY_SERVICES"

// Config is the services gateway's envconfig contract. The services gateway is
// the trusted frontend BFF edge (fronted by Cloudflare Workers): it terminates
// mTLS from the edge, verifies session access-token JWTs locally, and serves a
// curated gRPC BFF surface (ServicesGatewayService) that delegates to the
// backend services with the verified identity attached.
type Config struct {
	Debug bool `envconfig:"DEBUG" default:"false"`
	Port  int  `envconfig:"PORT" default:"8081"`

	// AuthnGRPCAddr hosts AuthnService.GetPublicKeys (JWKS source for JWT verification).
	AuthnGRPCAddr string `envconfig:"AUTHN_GRPC_ADDR" required:"true"`
	// ProfileGRPCAddr backs the BFF handlers.
	ProfileGRPCAddr string `envconfig:"PROFILE_GRPC_ADDR" required:"true"`

	// RedisAddr backs rate limiting.
	RedisAddr     string `envconfig:"REDIS_ADDR" required:"true"`
	RedisDatabase int    `envconfig:"REDIS_DATABASE" default:"0"`

	// TrustForwardHeader honours the peer-supplied client IP for anonymous
	// rate-limit keys (enable only behind the trusted edge). Required (explicit)
	// in production — no insecure default.
	TrustForwardHeader bool `envconfig:"TRUST_FORWARD_HEADER"`

	// SessionAccessTokenIssuer is the expected JWT `iss` (must match authn's
	// AUTHN_SESSION_ACCESS_TOKEN_ISSUER).
	SessionAccessTokenIssuer string `envconfig:"SESSION_ACCESS_TOKEN_ISSUER" required:"true"`
	JWKSCacheTTLSeconds      int    `envconfig:"JWKS_CACHE_TTL_SECONDS" default:"300"`

	// Rate limiting (fixed window per caller).
	RateLimit              int64 `envconfig:"RATE_LIMIT" default:"1200"`
	RateLimitWindowSeconds int   `envconfig:"RATE_LIMIT_WINDOW_SECONDS" default:"60"`

	// mTLS: when MTLSClientCAPath is set, the listener requires and verifies
	// client certs against that CA bundle; TLSCertPath/TLSKeyPath are then the
	// server's own certificate. All three must be set together.
	MTLSClientCAPath string `envconfig:"MTLS_CLIENT_CA_PATH"`
	TLSCertPath      string `envconfig:"TLS_CERT_PATH"`
	TLSKeyPath       string `envconfig:"TLS_KEY_PATH"`

	RequestTimeoutSeconds int `envconfig:"REQUEST_TIMEOUT_SECONDS" default:"15"`
}
