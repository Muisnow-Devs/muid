package app

import (
	"errors"
	"io"

	"google.golang.org/grpc"

	"sanzi.io/muid/internal/authn/account"
	authnent "sanzi.io/muid/internal/authn/ent"
	"sanzi.io/muid/internal/identity"
	"sanzi.io/muid/internal/otp"
	"sanzi.io/muid/internal/session"
	"sanzi.io/muid/internal/signature"
	"sanzi.io/muid/pkg/shared/kv"
	"sanzi.io/muid/pkg/shared/pubsub"
)

const (
	ConfigEnvPrefix = "AUTHN"
)

type Config struct {
	Debug bool `envconfig:"DEBUG" default:"false"`

	Port        int    `envconfig:"PORT"         default:"5314"`
	DatabaseURL string `envconfig:"DATABASE_URL"                required:"true"`
	RedisURL    string `envconfig:"REDIS_URL"                   required:"true"`
	NATSURL     string `envconfig:"NATS_URL"                    required:"true"`

	OTPSecretKey string `envconfig:"OTP_SECRET_KEY"            required:"true"`
	// OTPSendCooldownSeconds enforces a minimum delay between OTP sends for the same
	// auth transition (same transition id) and for the same normalized email recipient
	// across transitions. Zero disables send cooldown checks.
	OTPSendCooldownSeconds int `envconfig:"OTP_SEND_COOLDOWN_SECONDS"                 default:"60"`

	RequestTimeoutSeconds int `envconfig:"REQUEST_TIMEOUT_SECONDS" default:"10"`

	SignatureSecretName          string `envconfig:"SIGNATURE_SECRET_NAME"          default:""`
	SignatureKeyBits             int    `envconfig:"SIGNATURE_KEY_BITS"             default:"2048"`
	SignaturePreviousGenerations int    `envconfig:"SIGNATURE_PREVIOUS_GENERATIONS" default:"1"`
	SignatureRotationPeriodHours int    `envconfig:"SIGNATURE_ROTATION_PERIOD_HOURS" default:"720"`
	SecretManagerGCPProjectID    string `envconfig:"SECRET_MANAGER_GCP_PROJECT_ID"  default:""`
	SecretManagerGCPCredentials  string `envconfig:"SECRET_MANAGER_GCP_CREDENTIALS" default:""`

	// Third-party OAuth credentials
	GoogleOAuthClientID     string `envconfig:"GOOGLE_OAUTH_CLIENT_ID"     default:""`
	GoogleOAuthClientSecret string `envconfig:"GOOGLE_OAUTH_CLIENT_SECRET" default:""`
	GoogleRedirectURL       string `envconfig:"GOOGLE_REDIRECT_URL"        default:"http://localhost:5314/auth/callback/google"`

	FacebookOAuthClientID     string `envconfig:"FACEBOOK_OAUTH_CLIENT_ID"     default:""`
	FacebookOAuthClientSecret string `envconfig:"FACEBOOK_OAUTH_CLIENT_SECRET" default:""`
	FacebookRedirectURL       string `envconfig:"FACEBOOK_REDIRECT_URL"        default:"http://localhost:5314/auth/callback/facebook"`

	GithubOAuthClientID     string `envconfig:"GITHUB_OAUTH_CLIENT_ID"     default:""`
	GithubOAuthClientSecret string `envconfig:"GITHUB_OAUTH_CLIENT_SECRET" default:""`
	GithubRedirectURL       string `envconfig:"GITHUB_REDIRECT_URL"        default:"http://localhost:5314/auth/callback/github"`

	// ProfileGRPCAddr is the Profile gRPC authority (host:port). Leave empty to skip dialing (signup flows will fail until set).
	ProfileGRPCAddr string `envconfig:"PROFILE_GRPC_ADDR"            default:""`
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

type InfraDependencies struct {
	GlobalConfig Config

	Redis kv.KVStore

	OTPStore        otp.OTPStore
	TransitionStore session.AuthTransitionStore
	SessionCache    session.SessionCache
	PubSub          pubsub.PubSub
	IdentityManager *identity.IdentityManager

	Accounts *account.Accounts

	SignatureManager signature.SignatureManager

	entClient   *authnent.Client
	profileConn *grpc.ClientConn
}

func (d *InfraDependencies) Close() error {
	var errs []error
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
	if d.SignatureManager != nil {
		err := d.SignatureManager.Close()
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
