// Package httpx provides the small HTTP scaffolding shared by the muid gateways:
// a graceful server wrapper that mirrors the gRPC services' Start/Stop shape,
// plus the common middleware chain (trace id, logging, recovery, security
// headers, CORS). Gateways compose these rather than each re-implementing them.
package httpx

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"sanzi.io/muid/pkg/log"
)

// Server wraps http.Server with a context-driven graceful lifecycle that
// matches the gRPC services' Start/Stop pattern.
type Server struct {
	name            string
	httpServer      *http.Server
	listener        net.Listener
	tls             bool
	shutdownTimeout time.Duration
}

// Config configures a Server.
type Config struct {
	// Name labels the server in logs (e.g. "gateway-public").
	Name string
	// Addr is the listen address (":8080").
	Addr string
	// Handler is the root handler (already wrapped with middleware).
	Handler http.Handler
	// TLSConfig, when non-nil, serves HTTPS (e.g. mTLS for the services gateway).
	TLSConfig *tls.Config
	// ReadHeaderTimeout guards against slow-loris; defaults to 10s.
	ReadHeaderTimeout time.Duration
	// ShutdownTimeout bounds graceful drain; defaults to 15s.
	ShutdownTimeout time.Duration
}

// NewServer binds the listener and prepares the server.
func NewServer(cfg Config) (*Server, error) {
	if cfg.ReadHeaderTimeout <= 0 {
		cfg.ReadHeaderTimeout = 10 * time.Second
	}
	if cfg.ShutdownTimeout <= 0 {
		cfg.ShutdownTimeout = 15 * time.Second
	}
	listener, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		return nil, fmt.Errorf("httpx: listen %q: %w", cfg.Addr, err)
	}
	return &Server{
		name: cfg.Name,
		httpServer: &http.Server{
			Handler:           cfg.Handler,
			TLSConfig:         cfg.TLSConfig,
			ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		},
		listener:        listener,
		tls:             cfg.TLSConfig != nil,
		shutdownTimeout: cfg.ShutdownTimeout,
	}, nil
}

// Start serves until ctx is cancelled, then drains gracefully.
func (s *Server) Start(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() {
		log.Printf("%s listening on %s (tls=%t)", s.name, s.listener.Addr().String(), s.tls)
		if s.tls {
			errCh <- s.httpServer.ServeTLS(s.listener, "", "")
		} else {
			errCh <- s.httpServer.Serve(s.listener)
		}
	}()

	select {
	case <-ctx.Done():
		return s.Stop()
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// Stop drains in-flight requests within the configured shutdown timeout.
func (s *Server) Stop() error {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), s.shutdownTimeout)
	defer cancel()
	return s.httpServer.Shutdown(shutdownCtx)
}
