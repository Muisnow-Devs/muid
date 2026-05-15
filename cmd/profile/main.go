package main

import (
	"context"
	"fmt"
	"log"
	"os/signal"
	"syscall"

	"sanzi.io/muid/internal/profile/app"
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

	infra, err := app.NewInfra(ctx, cfg)
	if err != nil {
		return fmt.Errorf("init infra: %w", err)
	}

	papp, err := app.NewProfileApp(infra)
	if err != nil {
		return fmt.Errorf("create app: %w", err)
	}
	defer papp.Stop()

	go func() {
		err := papp.Start(ctx)
		errChan <- fmt.Errorf("app start failed: %w", err)
	}()

	select {
	case <-ctx.Done():
		log.Println("Shutting down gracefully...")
		return nil
	case err := <-errChan:
		return err
	}
}
