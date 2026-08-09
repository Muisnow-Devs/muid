package main

import (
	"context"
	"fmt"
	"os/signal"
	"syscall"

	"sanzi.io/muid/internal/gatewayservices/app"
	"sanzi.io/muid/pkg/errutil"
	"sanzi.io/muid/pkg/log"
	"sanzi.io/muid/pkg/shared"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("Application error: %v", err)
	}
}

func run() error {
	ctx, cancel := signal.NotifyContext(
		context.Background(),
		syscall.SIGINT,
		syscall.SIGTERM,
	)
	defer cancel()

	cfg, err := shared.LoadConfig[app.Config](app.ConfigEnvPrefix)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("validate config: %w", err)
	}

	infra, err := app.NewInfra(ctx, cfg)
	if err != nil {
		return fmt.Errorf("init infra: %w", err)
	}

	gateway, err := app.NewApp(infra)
	if err != nil {
		errutil.Close(infra)
		return fmt.Errorf("create app: %w", err)
	}
	return gateway.Run(ctx)
}
