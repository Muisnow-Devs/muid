// Package httpx provides the small HTTP scaffolding shared by the muid gateways:
// a graceful server wrapper with a context-owned lifecycle,
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
	// ReadTimeout bounds reading the complete request, including its body;
	// defaults to 30s.
	ReadTimeout time.Duration
	// ReadHeaderTimeout guards against slow-loris; defaults to 10s.
	ReadHeaderTimeout time.Duration
	// WriteTimeout bounds writing the response; defaults to at least 30s and is
	// kept above RequestTimeout.
	WriteTimeout time.Duration
	// IdleTimeout bounds keep-alive connections; defaults to 60s.
	IdleTimeout time.Duration
	// RequestTimeout bounds application handling after the request body has been
	// accepted; defaults to 15s.
	RequestTimeout time.Duration
	// MaxHeaderBytes bounds request headers; defaults to 1 MiB.
	MaxHeaderBytes int
	// ShutdownTimeout bounds graceful drain; defaults to at least 15s and is
	// kept above RequestTimeout.
	ShutdownTimeout time.Duration
}

const (
	defaultReadTimeout       = 30 * time.Second
	defaultReadHeaderTimeout = 10 * time.Second
	defaultWriteTimeout      = 30 * time.Second
	defaultIdleTimeout       = 60 * time.Second
	defaultRequestTimeout    = 15 * time.Second
	defaultShutdownTimeout   = 15 * time.Second
	defaultMaxHeaderBytes    = 1 << 20
	defaultMaxBodyBytes      = int64(1 << 20)
)

// NewServer binds the listener and prepares the server.
func NewServer(cfg Config) (*Server, error) {
	applyDefaults(&cfg)

	listener, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		return nil, fmt.Errorf("httpx: listen %q: %w", cfg.Addr, err)
	}

	return &Server{
		name: cfg.Name,
		httpServer: &http.Server{
			Handler:           cfg.Handler,
			TLSConfig:         cfg.TLSConfig,
			ReadTimeout:       cfg.ReadTimeout,
			ReadHeaderTimeout: cfg.ReadHeaderTimeout,
			WriteTimeout:      cfg.WriteTimeout,
			IdleTimeout:       cfg.IdleTimeout,
			MaxHeaderBytes:    cfg.MaxHeaderBytes,
		},
		listener:        listener,
		tls:             cfg.TLSConfig != nil,
		shutdownTimeout: cfg.ShutdownTimeout,
	}, nil
}

func applyDefaults(cfg *Config) {
	if cfg.ReadTimeout <= 0 {
		cfg.ReadTimeout = defaultReadTimeout
	}
	if cfg.ReadHeaderTimeout <= 0 {
		cfg.ReadHeaderTimeout = defaultReadHeaderTimeout
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = defaultIdleTimeout
	}
	if cfg.RequestTimeout <= 0 {
		cfg.RequestTimeout = defaultRequestTimeout
	}
	if cfg.WriteTimeout <= 0 {
		cfg.WriteTimeout = defaultWriteTimeout
		if requestWriteTimeout := cfg.RequestTimeout + 5*time.Second; requestWriteTimeout > cfg.WriteTimeout {
			cfg.WriteTimeout = requestWriteTimeout
		}
	}
	if cfg.MaxHeaderBytes <= 0 {
		cfg.MaxHeaderBytes = defaultMaxHeaderBytes
	}
	if cfg.ShutdownTimeout <= 0 {
		cfg.ShutdownTimeout = defaultShutdownTimeout
		if requestDrainTimeout := cfg.RequestTimeout + 5*time.Second; requestDrainTimeout > cfg.ShutdownTimeout {
			cfg.ShutdownTimeout = requestDrainTimeout
		}
	}
}

// Run serves until ctx is cancelled or serving fails. Cancellation triggers one
// bounded graceful drain; connections are forcibly closed if that budget is
// exhausted.
func (s *Server) Run(ctx context.Context) error {
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
		shutdownErr := s.shutdown()
		serveErr := <-errCh
		if shutdownErr != nil {
			return shutdownErr
		}
		return normalizeServeError(serveErr)
	case err := <-errCh:
		serveErr := normalizeServeError(err)
		if serveErr == nil {
			return nil
		}
		return errors.Join(serveErr, s.shutdown())
	}
}

func (s *Server) shutdown() error {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), s.shutdownTimeout)
	defer cancel()

	err := s.httpServer.Shutdown(shutdownCtx)
	listenerErr := s.listener.Close()
	if err == nil {
		if listenerErr != nil && !errors.Is(listenerErr, net.ErrClosed) {
			return listenerErr
		}
		return nil
	}
	closeErr := s.httpServer.Close()
	if closeErr != nil && !errors.Is(closeErr, http.ErrServerClosed) {
		return errors.Join(err, closeErr)
	}
	return err
}

func normalizeServeError(err error) error {
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}
