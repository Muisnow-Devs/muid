package main

import (
	"context"
	"fmt"
	"log"
	"os/signal"
	"syscall"

	"sanzi.io/muid/internal/authn/app"
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
		errChan <- fmt.Errorf("load config: %w", err)
	}

	infra, err := app.NewAuthnInfra(ctx, cfg)
	if err != nil {
		errChan <- fmt.Errorf("init infra: %w", err)
	}

	authnApp, err := app.NewAuthnApp(ctx, infra)
	if err != nil {
		infra.Close()
		errChan <- fmt.Errorf("create app: %w", err)
	}

	go func() {
		err := authnApp.Start(ctx)
		errChan <- fmt.Errorf("app start failed: %w", err)
	}()

	select {
	case <-ctx.Done():
		log.Println("Shutting down gracefully...")
		authnApp.Stop()
		return nil
	case err := <-errChan:
		return err
	}
}
