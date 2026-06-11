package app

import (
	"context"

	authzgrpc "sanzi.io/muid/internal/authz/grpc"
)

type AuthzApp struct {
	server             *AuthzGRPC
	dependencyInjector *InfraDependencies
}

func NewAuthzApp(ctx context.Context, infra *InfraDependencies) (*AuthzApp, error) {
	handler := authzgrpc.NewGRPCHandler(authzgrpc.HandlerConfig{
		SignatureManager: infra.SignatureManager,
		DB:               infra.entClient,
	})
	service, err := NewAuthzGRPC(infra.GlobalConfig, handler, nil)
	if err != nil {
		return nil, err
	}

	return &AuthzApp{
		server:             service,
		dependencyInjector: infra,
	}, nil
}

func (app *AuthzApp) Start(ctx context.Context) error {
	if app.dependencyInjector.SignatureManager != nil {
		err := app.dependencyInjector.SignatureManager.Start(ctx)
		if err != nil {
			return err
		}
	}

	return app.server.Start(ctx)
}

func (app *AuthzApp) Stop() {
	app.server.Stop()
	app.dependencyInjector.Close()
}
