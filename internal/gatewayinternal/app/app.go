package app

import (
	"context"
	"fmt"

	"sanzi.io/muid/pkg/errutil"
	"sanzi.io/muid/pkg/gateway/httpx"
)

// App is the internal gateway application.
type App struct {
	server *httpx.Server
	infra  *InfraDependencies
}

// NewApp wires the admin router and HTTP server from infra.
func NewApp(infra *InfraDependencies) (*App, error) {
	server, err := httpx.NewServer(httpx.Config{
		Name:    "gateway-internal",
		Addr:    fmt.Sprintf(":%d", infra.GlobalConfig.Port),
		Handler: newHandler(infra),
	})
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
	errutil.Discard(a.server.Stop())
	errutil.Discard(a.infra.Close())
}
