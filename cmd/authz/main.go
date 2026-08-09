package main

import (
	"context"
	"fmt"
	"os/signal"
	"syscall"

	"sanzi.io/muid/internal/authz/app"
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

	errChan := make(chan error, 1)

	cfg, err := shared.LoadConfig[app.Config](app.ConfigEnvPrefix)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if err = cfg.Validate(); err != nil {
		return fmt.Errorf("validate config: %w", err)
	}

	infra, err := app.NewAuthzInfra(ctx, cfg)
	if err != nil {
		return fmt.Errorf("init infra: %w", err)
	}

	authzApp, err := app.NewAuthzApp(ctx, infra)
	if err != nil {
		infra.Close()
		return fmt.Errorf("create app: %w", err)
	}

	go func() {
		err := authzApp.Start(ctx)
		errChan <- fmt.Errorf("app start failed: %w", err)
	}()

	select {
	case <-ctx.Done():
		log.Println("Shutting down gracefully...")
		authzApp.Stop()
		return nil
	case err := <-errChan:
		return err
	}
}
