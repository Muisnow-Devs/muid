// Package mtls builds *tls.Config values that require and verify client
// certificates. The trust anchor is a RootProvider so pinned edge public keys
// can be swapped in later without touching the listener wiring.
package mtls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
)

// ErrNoRoots is returned when a provider yields an empty trust pool.
var ErrNoRoots = errors.New("mtls: no client CA roots configured")

// RootProvider supplies the set of CAs trusted to sign client certificates.
type RootProvider interface {
	Roots(ctx context.Context) (*x509.CertPool, error)
}

// StaticRoots is a fixed PEM-bundle RootProvider.
type StaticRoots struct {
	pool *x509.CertPool
}

// NewStaticRootsFromPEM parses one or more concatenated PEM CA certificates.
func NewStaticRootsFromPEM(pemBundle []byte) (*StaticRoots, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBundle) {
		return nil, ErrNoRoots
	}
	return &StaticRoots{pool: pool}, nil
}

// Roots implements RootProvider.
func (s *StaticRoots) Roots(context.Context) (*x509.CertPool, error) {
	if s == nil || s.pool == nil {
		return nil, ErrNoRoots
	}
	return s.pool, nil
}

// ServerTLSConfig returns a TLS config that presents serverCert and requires a
// client certificate verified against provider's roots. Roots are resolved per
// handshake via GetConfigForClient so a dynamic provider is picked up live.
func ServerTLSConfig(provider RootProvider, serverCert tls.Certificate) (*tls.Config, error) {
	if provider == nil {
		return nil, ErrNoRoots
	}
	// Validate eagerly so misconfiguration fails at startup, not first handshake.
	if _, err := provider.Roots(context.Background()); err != nil {
		return nil, err
	}

	base := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}
	base.GetConfigForClient = func(_ *tls.ClientHelloInfo) (*tls.Config, error) {
		pool, err := provider.Roots(context.Background())
		if err != nil {
			return nil, err
		}
		cfg := base.Clone()
		cfg.GetConfigForClient = nil
		cfg.ClientCAs = pool
		return cfg, nil
	}
	return base, nil
}
