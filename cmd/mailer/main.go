package main

import (
	"context"
	"fmt"
	"log"
	"os/signal"
	"syscall"

	"sanzi.io/muid/internal/mailer/app"
	"sanzi.io/muid/pkg/errutil"
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

	infra, err := app.NewInfra(cfg)
	if err != nil {
		errChan <- fmt.Errorf("init infra: %w", err)
	}
	defer func() { errutil.Discard(infra.Close()) }()

	if err := app.RegisterSubscribers(ctx, infra); err != nil {
		errChan <- fmt.Errorf("register subscribers: %w", err)
	}

	select {
	case <-ctx.Done():
		log.Println("Shutting down gracefully...")
		return nil
	case err := <-errChan:
		return err
	}
}
