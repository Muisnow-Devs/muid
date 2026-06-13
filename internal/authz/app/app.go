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
	handlerCfg := authzgrpc.HandlerConfig{
		Manager:       infra.PolicyManager,
		ProfileClient: infra.ProfileClient,
	}
	handlers := Handlers{
		Service:  authzgrpc.NewGRPCHandler(handlerCfg),
		User:     authzgrpc.NewUserHandler(handlerCfg),
		OrgAdmin: authzgrpc.NewOrgAdminHandler(handlerCfg),
		Admin:    authzgrpc.NewAdminHandler(handlerCfg),
	}
	service, err := NewAuthzGRPC(infra.GlobalConfig, handlers, nil)
	if err != nil {
		return nil, err
	}

	return &AuthzApp{
		server:             service,
		dependencyInjector: infra,
	}, nil
}

func (app *AuthzApp) Start(ctx context.Context) error {
	// Keep replicas' in-memory policies coherent across mutations.
	err := app.dependencyInjector.PolicyManager.StartReplicaSync(ctx)
	if err != nil {
		return err
	}
	return app.server.Start(ctx)
}

func (app *AuthzApp) Stop() {
	app.server.Stop()
	app.dependencyInjector.Close()
}
