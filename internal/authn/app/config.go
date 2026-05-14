package app

import (
	"errors"
	"io"

	"google.golang.org/grpc"

	authnent "sanzi.io/muid/internal/authn/ent"
	"sanzi.io/muid/internal/authn/infra/account"
	"sanzi.io/muid/internal/identity"
	"sanzi.io/muid/internal/otp"
	"sanzi.io/muid/internal/session"
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

	OTPSecretKey string `envconfig:"OTP_SECRET_KEY" required:"true"`

	RequestTimeoutSeconds int `envconfig:"REQUEST_TIMEOUT_SECONDS" default:"10"`

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
}

type InfraDependencies struct {
	GlobalConfig Config

	Redis kv.KVStore

	OTPStore        otp.OTPStore
	TransitionStore session.AuthTransitionStore
	PubSub          pubsub.PubSub
	IdentityManager *identity.IdentityManager

	Accounts *account.Services

	entClient   *authnent.Client
	profileConn *grpc.ClientConn
}

func (d *InfraDependencies) Close() error {
	var errs []error
	if d.profileConn != nil {
		if err := d.profileConn.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if d.entClient != nil {
		if err := d.entClient.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if d.PubSub != nil {
		if c, ok := d.PubSub.(io.Closer); ok {
			if err := c.Close(); err != nil {
				errs = append(errs, err)
			}
		}
	}
	if d.Redis != nil {
		if c, ok := d.Redis.(io.Closer); ok {
			if err := c.Close(); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}
