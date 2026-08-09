package httpx

import (
	"context"
	"net/http"
	"testing"
	"time"

	"sanzi.io/muid/pkg/errutil"
)

func TestNewServerAppliesResourceDefaults(t *testing.T) {
	t.Parallel()

	server, err := NewServer(Config{
		Name:    "test",
		Addr:    "127.0.0.1:0",
		Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	t.Cleanup(func() { errutil.Close(server.listener) })

	if server.httpServer.ReadTimeout != defaultReadTimeout {
		t.Fatalf("ReadTimeout = %v", server.httpServer.ReadTimeout)
	}
	if server.httpServer.ReadHeaderTimeout != defaultReadHeaderTimeout {
		t.Fatalf("ReadHeaderTimeout = %v", server.httpServer.ReadHeaderTimeout)
	}
	if server.httpServer.WriteTimeout != defaultWriteTimeout {
		t.Fatalf("WriteTimeout = %v", server.httpServer.WriteTimeout)
	}
	if server.httpServer.IdleTimeout != defaultIdleTimeout {
		t.Fatalf("IdleTimeout = %v", server.httpServer.IdleTimeout)
	}
	if server.httpServer.MaxHeaderBytes != defaultMaxHeaderBytes {
		t.Fatalf("MaxHeaderBytes = %d", server.httpServer.MaxHeaderBytes)
	}
}

func TestServerRunWithCanceledContextReturns(t *testing.T) {
	t.Parallel()

	server, err := NewServer(Config{
		Name:            "test",
		Addr:            "127.0.0.1:0",
		Handler:         http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
		ShutdownTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx) }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run() did not return after cancellation")
	}
}

func TestApplyDefaultsKeepsWriteAndDrainBudgetsAboveRequest(t *testing.T) {
	t.Parallel()

	cfg := Config{RequestTimeout: time.Minute}
	applyDefaults(&cfg)
	want := time.Minute + 5*time.Second
	if cfg.WriteTimeout != want {
		t.Fatalf("WriteTimeout = %v, want %v", cfg.WriteTimeout, want)
	}
	if cfg.ShutdownTimeout != want {
		t.Fatalf("ShutdownTimeout = %v, want %v", cfg.ShutdownTimeout, want)
	}
}
