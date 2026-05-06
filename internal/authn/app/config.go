package app

import (
	"errors"
	"io"

	"sanzi.io/muid/internal/identity"
	"sanzi.io/muid/internal/otp"
	"sanzi.io/muid/internal/session"
	"sanzi.io/muid/pkg/shared/pubsub"
)

const (
	ConfigEnvPrefix = "AUTHN"
)

type Config struct {
	Debug bool `envconfig:"DEBUG" default:"false"`

	Port        int    `envconfig:"PORT" default:"5314"`
	DatabaseURL string `envconfig:"DATABASE_URL" required:"true"`
	RedisURL    string `envconfig:"REDIS_URL" required:"true"`
	NATSURL     string `envconfig:"NATS_URL" required:"true"`

	OTPSecretKey string `envconfig:"OTP_SECRET_KEY" required:"true"`

	RequestTimeoutSeconds int `envconfig:"REQUEST_TIMEOUT_SECONDS" default:"10"`

	// Third-party OAuth credentials
	GoogleOAuthClientID     string `envconfig:"GOOGLE_OAUTH_CLIENT_ID" default:""`
	GoogleOAuthClientSecret string `envconfig:"GOOGLE_OAUTH_CLIENT_SECRET" default:""`
	GoogleRedirectURL       string `envconfig:"GOOGLE_REDIRECT_URL" default:"http://localhost:5314/auth/callback/google"`

	FacebookOAuthClientID     string `envconfig:"FACEBOOK_OAUTH_CLIENT_ID" default:""`
	FacebookOAuthClientSecret string `envconfig:"FACEBOOK_OAUTH_CLIENT_SECRET" default:""`
	FacebookRedirectURL       string `envconfig:"FACEBOOK_REDIRECT_URL" default:"http://localhost:5314/auth/callback/facebook"`

	GithubOAuthClientID     string `envconfig:"GITHUB_OAUTH_CLIENT_ID" default:""`
	GithubOAuthClientSecret string `envconfig:"GITHUB_OAUTH_CLIENT_SECRET" default:""`
	GithubRedirectURL       string `envconfig:"GITHUB_REDIRECT_URL" default:"http://localhost:5314/auth/callback/github"`
}

type InfraDependencies struct {
	GlobalConfig Config

	// Add other dependencies like database connections, Redis clients, etc. here
	OTPStore        otp.OTPStore
	TransitionStore session.AuthTransitionStore
	PubSub          pubsub.PubSub
	IdentityManager *identity.IdentityManager
}

func closeAll(closers ...any) error {
	var errs []error

	for i := len(closers) - 1; i >= 0; i-- {
		if c, ok := closers[i].(io.Closer); ok {
			if err := c.Close(); err != nil {
				errs = append(errs, err)
			}
		}
	}

	return errors.Join(errs...)
}

func (d *InfraDependencies) Close() error {
	return closeAll(
		d.OTPStore,
		d.TransitionStore,
		d.PubSub,
	)
}
