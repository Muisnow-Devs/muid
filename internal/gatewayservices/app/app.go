package app

import (
	"context"

	servicesgrpc "sanzi.io/muid/internal/gatewayservices/grpc"
	"sanzi.io/muid/pkg/errutil"
)

// App is the services gateway application.
type App struct {
	server *ServicesGRPC
	infra  *InfraDependencies
}

// NewApp wires the BFF handler and gRPC server from infra.
func NewApp(infra *InfraDependencies) (*App, error) {
	handler := servicesgrpc.NewHandler(infra.Account, infra.Profile)
	server, err := NewServicesGRPC(infra, handler, nil)
	if err != nil {
		return nil, err
	}
	return &App{server: server, infra: infra}, nil
}

// Run serves until cancellation or failure, drains the gRPC server, and then
// releases all infrastructure owned by the app.
func (a *App) Run(ctx context.Context) error {
	defer errutil.Close(a.infra)
	return a.server.Run(ctx)
}
