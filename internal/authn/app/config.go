package app

import (
	"errors"
	"io"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"google.golang.org/grpc"

	profilepb "sanzi.io/muid/api/proto/profile/v1"
	authnconfig "sanzi.io/muid/internal/authn/config"
	authnent "sanzi.io/muid/internal/authn/ent"
	"sanzi.io/muid/internal/identity"
	"sanzi.io/muid/internal/otp"
	"sanzi.io/muid/internal/session"
	"sanzi.io/muid/pkg/shared/kv"
	"sanzi.io/muid/pkg/shared/pubsub"
)

const (
	// ConfigEnvPrefix is the environment variable prefix for authn config.
	ConfigEnvPrefix = "AUTHN"
)

// Config holds the authn service configuration.
type Config struct {
	Debug bool `envconfig:"DEBUG" default:"false"`

	Port          int    `envconfig:"PORT"           default:"5314"`
	DatabaseURL   string `envconfig:"DATABASE_URL"                  required:"true"`
	RedisAddr     string `envconfig:"REDIS_ADDR"                    required:"true"`
	RedisDatabase int    `envconfig:"REDIS_DATABASE" default:"0"`
	NATSURL       string `envconfig:"NATS_URL"                      required:"true"`

	OTPSecretKey string `envconfig:"OTP_SECRET_KEY"            required:"true"`
	// OTPSendCooldownSeconds enforces a minimum delay between OTP sends for the same
	// auth transition (same transition id) and for the same normalized email recipient
	// across transitions. Zero disables send cooldown checks.
	OTPSendCooldownSeconds int `envconfig:"OTP_SEND_COOLDOWN_SECONDS"                 default:"60"`
	// MaxAuthAttempts is the maximum number of failed authentication attempts
	// (wrong code, wrong passkey, etc.) allowed before the transition session is
	// revoked. The same value is applied to the OTP challenge attempt counter so
	// the two limits are always in sync. Must be ≥ 1; defaults to 3.
	MaxAuthAttempts int `envconfig:"MAX_AUTH_ATTEMPTS"                         default:"3"`

	RequestTimeoutSeconds int `envconfig:"REQUEST_TIMEOUT_SECONDS" default:"10"`

	// LoginAlertSecureLink is the HTTPS URL embedded in login-alert mail (account security page).
	LoginAlertSecureLink string `envconfig:"LOGIN_ALERT_SECURE_LINK"`

	// OIDCClients configures enabled OIDC identity providers as a JSON array.
	OIDCClients authnconfig.OIDCClients `envconfig:"OIDC_CLIENTS_JSON" default:"[]"`

	// RPID is the Relying Party ID for Passkey (WebAuthn) operations, typically the effective domain name of the
	// application. It should be set to the root domain (e.g. "example.com" not "auth.example.com") if using subdomain
	// delegation with a valid delegation JSON file at the well-known location on the root domain.
	PasskeyRPID string `envconfig:"PASSKEY_RP_ID"           default:"localhost"`
	// PasskeyRPDisplayName is the user-friendly name for the Relying Party, shown in authenticator prompts.
	PasskeyRPDisplayName string `envconfig:"PASSKEY_RP_DISPLAY_NAME" default:"muid"`
	// PasskeyRPOrigins accepts a JSON array or comma-separated origins.
	PasskeyRPOrigins authnconfig.PasskeyOrigins `envconfig:"PASSKEY_RP_ORIGINS"      default:"'http://localhost','http://localhost:3000','https://localhost'"`

	// ProfileGRPCAddr is the Profile gRPC authority (host:port). Leave empty to skip dialing (signup flows will fail
	// until set).
	ProfileGRPCAddr string `envconfig:"PROFILE_GRPC_ADDR"            default:"localhost:5324"`
	// ProfileGRPCTimeoutSeconds bounds each outbound Profile RPC from authn.
	ProfileGRPCTimeoutSeconds int `envconfig:"PROFILE_GRPC_TIMEOUT_SECONDS" default:"10"`

	// Outbound Profile client resilience (retry + circuit breaker); see pkg/grpc_utils.
	ProfileGRPCMaxRetries            int  `envconfig:"PROFILE_GRPC_MAX_RETRIES"               default:"2"`
	ProfileGRPCRetryBackoffMillis    int  `envconfig:"PROFILE_GRPC_RETRY_BACKOFF_MILLIS"      default:"100"`
	ProfileGRPCRetryMaxBackoffMillis int  `envconfig:"PROFILE_GRPC_RETRY_MAX_BACKOFF_MILLIS"  default:"2000"`
	ProfileGRPCCBEnabled             bool `envconfig:"PROFILE_GRPC_CB_ENABLED"                default:"true"`
	ProfileGRPCCBConsecutiveFailures int  `envconfig:"PROFILE_GRPC_CB_CONSECUTIVE_FAILURES"   default:"5"`
	ProfileGRPCCBOpenSeconds         int  `envconfig:"PROFILE_GRPC_CB_OPEN_SECONDS"           default:"30"`
	ProfileGRPCCBHalfOpenMaxRequests int  `envconfig:"PROFILE_GRPC_CB_HALF_OPEN_MAX_REQUESTS" default:"3"`
}

// InfraDependencies holds the runtime dependencies for the authn app.
type InfraDependencies struct {
	GlobalConfig Config

	Redis kv.KVStore

	OTPStore                  otp.OTPStore
	TransitionStore           session.AuthTransitionStore
	SessionCache              session.SessionCache
	PubSub                    pubsub.PubSub
	WebAuthn                  *webauthn.WebAuthn
	ProfileCli                profilepb.ProfileServiceClient
	ProfileCallTimeoutSeconds time.Duration
	IdentityManager           *identity.IdentityManager

	entClient   *authnent.Client
	profileConn *grpc.ClientConn
}

// Close releases the owned dependencies.
func (d *InfraDependencies) Close() error {
	var errs []error
	if d.IdentityManager != nil {
		d.IdentityManager.Close()
	}
	if d.profileConn != nil {
		err := d.profileConn.Close()
		if err != nil {
			errs = append(errs, err)
		}
	}
	if d.entClient != nil {
		err := d.entClient.Close()
		if err != nil {
			errs = append(errs, err)
		}
	}
	if d.PubSub != nil {
		if c, ok := d.PubSub.(io.Closer); ok {
			err := c.Close()
			if err != nil {
				errs = append(errs, err)
			}
		}
	}
	if d.Redis != nil {
		if c, ok := d.Redis.(io.Closer); ok {
			err := c.Close()
			if err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}
