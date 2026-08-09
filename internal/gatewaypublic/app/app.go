package app

import (
	"context"
	"fmt"
	"time"

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
		Name:           "gateway-public",
		Addr:           fmt.Sprintf(":%d", infra.GlobalConfig.Port),
		Handler:        newHandler(infra),
		RequestTimeout: time.Duration(infra.GlobalConfig.RequestTimeoutSeconds) * time.Second,
	})
	if err != nil {
		return nil, err
	}
	return &App{server: server, infra: infra}, nil
}

// Run launches background workers, serves until cancellation or failure, drains
// the HTTP server, and then releases all infrastructure owned by the app.
func (a *App) Run(ctx context.Context) error {
	runCtx, cancel := context.WithCancel(ctx)
	defer errutil.Close(a.infra)
	defer cancel()

	a.infra.StartBackground(runCtx)
	return a.server.Run(runCtx)
}
