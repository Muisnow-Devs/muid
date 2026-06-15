package app

import (
	"context"

	servicesgrpc "sanzi.io/muid/internal/gatewayservices/grpc"
)

// App is the services gateway application.
type App struct {
	server *ServicesGRPC
	infra  *InfraDependencies
}

// NewApp wires the BFF handler and gRPC server from infra.
func NewApp(infra *InfraDependencies) (*App, error) {
	handler := servicesgrpc.NewHandler(infra.Profile)
	server, err := NewServicesGRPC(infra, handler, nil)
	if err != nil {
		return nil, err
	}
	return &App{server: server, infra: infra}, nil
}

// Start serves until ctx is cancelled.
func (a *App) Start(ctx context.Context) error {
	return a.server.Start(ctx)
}

// Stop drains the server and releases infrastructure.
func (a *App) Stop() {
	a.server.Stop()
	a.infra.Close()
}
