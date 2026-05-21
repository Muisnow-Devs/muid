package app

import (
	"context"

	"sanzi.io/muid/internal/authn/account"
	authngrpc "sanzi.io/muid/internal/authn/grpc"
	implIdentity "sanzi.io/muid/internal/authn/identity"
	"sanzi.io/muid/internal/identity"
	"sanzi.io/muid/internal/otp"
	"sanzi.io/muid/internal/session"
	"sanzi.io/muid/pkg/shared/pubsub"
)

type AuthnApp struct {
	server             *AuthnGRPC
	dependencyInjector *InfraDependencies
}

func NewAuthnApp(ctx context.Context, infra *InfraDependencies) (*AuthnApp, error) {
	handler := authngrpc.NewGRPCHandler(
		infra.IdentityManager,
		infra.TransitionStore,
		infra.Accounts,
		authngrpc.HandlerConfig{
			OTPSendCooldownSeconds: infra.GlobalConfig.OTPSendCooldownSeconds,
			SignatureManager:       infra.SignatureManager,
		},
	)
	service, err := NewAuthnGRPC(infra.GlobalConfig, handler, nil)
	if err != nil {
		return nil, err
	}

	return &AuthnApp{
		server:             service,
		dependencyInjector: infra,
	}, nil
}

func (app *AuthnApp) Start(ctx context.Context) error {
	if app.dependencyInjector.SignatureManager != nil {
		err := app.dependencyInjector.SignatureManager.Start(ctx)
		if err != nil {
			return err
		}
	}

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

	oidcProviders, err := oidcProviderConfigsFromEnv(config)
	if err != nil {
		return nil, err
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
