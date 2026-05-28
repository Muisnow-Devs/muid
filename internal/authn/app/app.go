package app

import (
	"context"

	authngrpc "sanzi.io/muid/internal/authn/grpc"
	"sanzi.io/muid/internal/identity/issuer"
	"sanzi.io/muid/internal/identity/policy"
	"sanzi.io/muid/internal/identity/resolver"
)

type AuthnApp struct {
	server             *AuthnGRPC
	dependencyInjector *InfraDependencies
}

func NewAuthnApp(ctx context.Context, infra *InfraDependencies) (*AuthnApp, error) {
	pol := policy.NewEntLinkPolicy(infra.entClient)
	res := resolver.NewEntUserResolver(
		infra.entClient,
		infra.ProfileCli,
		infra.ProfileCallTimeoutSeconds,
	)
	iss := issuer.NewEntSessionIssuer(infra.entClient, infra.SessionCache)

	handler := authngrpc.NewGRPCHandler(authngrpc.HandlerDependencies{
		DB:              infra.entClient,
		TransitionStore: infra.TransitionStore,
		PubSub:          infra.PubSub,
		SecureLink:      infra.GlobalConfig.LoginAlertSecureLink,
		Policy:          pol,
		Resolver:        res,
		Issuer:          iss,
		IdentityManager: infra.IdentityManager,
	})
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
	return app.server.Start(ctx)
}

func (app *AuthnApp) Stop() {
	app.server.Stop()
	app.dependencyInjector.Close()
}
