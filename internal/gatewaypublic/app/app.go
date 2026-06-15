package app

import (
	"context"
	"fmt"

	"sanzi.io/muid/pkg/errutil"
	"sanzi.io/muid/pkg/gateway/httpx"
)

// App is the public gateway application.
type App struct {
	server *httpx.Server
	infra  *InfraDependencies
}

// NewApp wires the routed handler and HTTP server from infra.
func NewApp(infra *InfraDependencies) (*App, error) {
	server, err := httpx.NewServer(httpx.Config{
		Name:    "gateway-public",
		Addr:    fmt.Sprintf(":%d", infra.GlobalConfig.Port),
		Handler: newHandler(infra),
	})
	if err != nil {
		return nil, err
	}
	return &App{server: server, infra: infra}, nil
}

// Start launches background workers then serves until ctx is cancelled.
func (a *App) Start(ctx context.Context) error {
	a.infra.StartBackground(ctx)
	return a.server.Start(ctx)
}

// Stop drains the server and releases infrastructure.
func (a *App) Stop() {
	errutil.Discard(a.server.Stop())
	errutil.Discard(a.infra.Close())
}
