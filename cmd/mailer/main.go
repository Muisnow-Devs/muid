package main

import (
	"fmt"
	"log"
	"os"
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
	cfg, err := shared.LoadConfig[app.Config](app.ConfigEnvPrefix)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	infra, err := app.NewInfra(cfg)
	if err != nil {
		return fmt.Errorf("init infra: %w", err)
	}
	defer func() { errutil.Discard(infra.Close()) }()

	if err := app.RegisterSubscribers(infra); err != nil {
		return fmt.Errorf("register subscribers: %w", err)
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	return nil
}
