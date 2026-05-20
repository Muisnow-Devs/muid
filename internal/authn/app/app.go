package app

import (
	"context"

	"sanzi.io/muid/internal/authn/infra/account"
	implIdentity "sanzi.io/muid/internal/authn/infra/identity"
	"sanzi.io/muid/internal/identity"
	"sanzi.io/muid/internal/otp"
	"sanzi.io/muid/internal/session"
	"sanzi.io/muid/pkg/shared/pubsub"
)

type AuthnApp struct {
	server             *AuthnService
	dependencyInjector *InfraDependencies
}

func NewAuthnApp(ctx context.Context, infra *InfraDependencies) (*AuthnApp, error) {
	handler := CreateGRPCHandler(infra)
	service, err := NewAuthnService(infra.GlobalConfig, handler, nil)
	if err != nil {
		return nil, err
	}

	return &AuthnApp{
		server:             service,
		dependencyInjector: infra,
	}, nil
}

func (app *AuthnApp) Start(ctx context.Context) error {
	return app.server.Start(ctx)
}

func (app *AuthnApp) Stop() {
	app.server.Stop()
	app.dependencyInjector.Close()
}

func InitializeIdentityManager(
	ctx context.Context,
	config Config,
	transitionStore session.AuthTransitionStore,
	otpStore otp.OTPStore,
	pubSub pubsub.PubSub,
	accounts *account.Accounts,
) (*identity.IdentityManager, error) {
	providers := []identity.IdentityProvider{
		implIdentity.NewEmailIdentityProvider(otpStore, transitionStore, pubSub, accounts),
		implIdentity.NewPasskeyIdentityProvider(transitionStore, accounts, pubSub),
	}

	oidcProviders := []implIdentity.OIDCProviderConfig{
		{
			Name:         "google",
			Issuer:       implIdentity.GOOGLE_OIDC_PROVIDER_URL,
			ClientID:     config.GoogleOAuthClientID,
			ClientSecret: config.GoogleOAuthClientSecret,
			RedirectURL:  config.GoogleRedirectURL,
		},
		{
			Name:         "github",
			Issuer:       implIdentity.GITHUB_OIDC_PROVIDER_URL,
			ClientID:     config.GithubOAuthClientID,
			ClientSecret: config.GithubOAuthClientSecret,
			RedirectURL:  config.GithubRedirectURL,
		},
		{
			Name:         "facebook",
			Issuer:       implIdentity.FACEBOOK_OIDC_PROVIDER_URL,
			ClientID:     config.FacebookOAuthClientID,
			ClientSecret: config.FacebookOAuthClientSecret,
			RedirectURL:  config.FacebookRedirectURL,
		},
	}

	for _, cfg := range oidcProviders {
		p, err := implIdentity.NewOIDCProvider(ctx, cfg, transitionStore, accounts)
		if err != nil {
			return nil, &OIDCProviderInitError{Name: cfg.Name, Err: err}
		}

		providers = append(providers, p)
	}

	identityManager := identity.NewIdentityManager(transitionStore, providers...)
	return identityManager, nil
}
