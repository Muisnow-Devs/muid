package main

import (
	"context"
	"fmt"
	"log"
	"os"
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
	ctx := context.Background()

	cfg, err := shared.LoadConfig[app.Config](app.ConfigEnvPrefix)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	infra, err := app.NewAuthnInfra(ctx, cfg)
	if err != nil {
		return fmt.Errorf("init infra: %w", err)
	}

	authnApp, err := app.NewAuthnApp(ctx, infra)
	if err != nil {
		infra.Close()
		return fmt.Errorf("create app: %w", err)
	}

	go func() {
		if err := authnApp.Start(ctx); err != nil {
			log.Printf("app start failed: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	authnApp.Stop()
	return nil
}
